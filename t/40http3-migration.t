use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::IP;
use Path::Tiny qw(path);
use Socket qw(SOCK_DGRAM);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
subtest "v4->v4" => sub {
    run_case("127.0.0.1");
};

subtest "v6->v6" => sub {
    my $has_v6 = IO::Socket::IP->new(
        LocalHost => "::1",
        LocalPort => 0,
        Proto     => "udp",
        Type      => SOCK_DGRAM,
    ) ? 1 : 0;
    plan skip_all => "IPv6 may not be available"
        unless $has_v6;
    run_case("::1");
};

done_testing;

sub run_case {
    my ($host) = @_;
    my $access_log = "$tempdir/access-log";
    unlink $access_log;
    my $quic_port = empty_port({host => $host, proto => "udp"});
    my $conf = <<"EOT";
num-threads: 1
access-log:
  path: $access_log
  format: "%{http3.quic-stats}x"
listen:
  - type: quic
    host: $host
    port: $quic_port
    ssl:
      key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /echo:
        mruby.handler: |
          Proc.new do |env|
            body = env["rack.input"].read
            [200, {}, [body]]
          end
EOT
    my $server = spawn_h2o_raw($conf, [
        {host => $host, port => $quic_port, proto => "udp"},
    ]);
    my ($forwarder, $forwarder_port) = spawn_forwarder($quic_port, 20, $host);

    my $body_size = 1200;
    my $resp = `$client_prog -3 100 -b $body_size -c 20 -i 100 https://127.0.0.1:$forwarder_port/echo 2>$tempdir/client.err`;
    is $?, 0, "client exited successfully" or diag path("$tempdir/client.err")->slurp;
    is length($resp), $body_size, "response length matches request body size";
    ok $resp =~ /^a+$/s, "echo response matches request body";

    sleep 0.2;
    my $stats_line = last_nonempty_line($access_log);
    my %stats = map { split /=/, $_, 2 } split /,/, $stats_line;

    cmp_ok($stats{'num-paths.created'} || 0, '>=', 1, "server created a migrated path");
    cmp_ok($stats{'num-paths.migration-elicited'} || 0, '>=', 1, "server observed migration");
    cmp_ok($stats{'num-paths.validated'} || 0, '>=', 1, "server validated the migrated path");
    cmp_ok($stats{'num-paths.promoted'} || 0, '>=', 1, "server promoted the migrated path");

    undef $forwarder;
    undef $server;
}

sub spawn_forwarder {
    my ($upstream_port, $switch_after, $host) = @_;

    my $listen_sock = IO::Socket::IP->new(
        LocalHost => "127.0.0.1",
        LocalPort => 0,
        Proto     => "udp",
        Type      => SOCK_DGRAM,
    ) or die "failed to create listen socket:$!";
    my $initial_upstream = IO::Socket::IP->new(
        LocalHost => $host,
        PeerHost  => $host,
        PeerPort  => $upstream_port,
        Proto     => "udp",
        Type      => SOCK_DGRAM,
    ) or die "failed to create initial upstream socket:$!";
    my $migrated_upstream = IO::Socket::IP->new(
        LocalHost => $host,
        PeerHost  => $host,
        PeerPort  => $upstream_port,
        Proto     => "udp",
        Type      => SOCK_DGRAM,
    ) or die "failed to create migrated upstream socket:$!";

    my $listen_port = $listen_sock->sockport;
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        local $SIG{TERM} = sub { exit 0 };

        my $selector = IO::Select->new($listen_sock, $initial_upstream, $migrated_upstream);
        my $client_addr;
        my $active_upstream = $initial_upstream;
        my $num_upstream_packets = 0;

        while (1) {
            for my $sock ($selector->can_read) {
                my $peer = recv($sock, my $buf = "", 2048, 0);
                next unless defined $peer;
                next unless length $buf;

                if (fileno($sock) == fileno($listen_sock)) {
                    $client_addr = $peer if !defined $client_addr;
                    die "unexpected client peer change"
                        if defined $client_addr && $client_addr ne $peer;

                    ++$num_upstream_packets;
                    $active_upstream = $migrated_upstream if $num_upstream_packets > $switch_after;
                    send($active_upstream, $buf, 0) == length($buf)
                        or die "failed to forward client packet:$!";
                } else {
                    next unless defined $client_addr;
                    send($listen_sock, $buf, 0, $client_addr) == length($buf)
                        or die "failed to forward server packet:$!";
                }
            }
        }
        exit 0;
    }

    return (
        make_guard(sub {
            kill 'TERM', $pid;
            waitpid($pid, 0);
        }),
        $listen_port,
    );
}

sub last_nonempty_line {
    my $fn = shift;
    open my $fh, "<", $fn
        or die "failed to open file:$fn:$!";
    my $line = "";
    while (my $candidate = <$fh>) {
        chomp $candidate;
        $line = $candidate if length $candidate;
    }
    close $fh;
    return $line;
}
