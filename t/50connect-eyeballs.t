use strict;
use warnings;
use IO::Socket::IP;
use Test::More;
use Time::HiRes qw(time);
use Socket qw(SOCK_STREAM);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $injectaddr = do {
    my $suffix = $^O eq "darwin" ? "dylib" : "so";
    my $fn = bindir() . "/libinjectaddr.$suffix";
    plan skip_all => "$fn does not exist"
        unless -e $fn;
    $^O eq "darwin" ? sub {
        local $ENV{DYLD_INSERT_LIBRARIES} = $fn;
        local $ENV{DYLD_FORCE_FLAT_NAMESPACE} = $fn;
        shift->();
    } : sub {
        local $ENV{LD_PRELOAD} = $fn;
        shift->();
    };
};

plan skip_all => "injectaddr does not work (maybe ASAN is on?)" unless
    $injectaddr->(sub { system("ls > /dev/null") == 0 });

# IPv6 is not available on docker on GitHub Actions; see https://twitter.com/kazuho/status/1465310656303796224
my ($v6_guard, $v6_port) = create_listener("::1")
    or plan skip_all => "IPv6 may not be available:$!";
my ($v4_guard, $v4_port) = create_listener("127.0.0.1")
    or die "failed to create IPv4 listener:$!";
my $blackhole_ip_v4 = find_blackhole_ip();
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = $injectaddr->(sub {
    spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
         proxy.connect:
           - "+*"
         proxy.timeout.connect: 10000
         proxy.happy-eyeballs.name-resolution-delay: 500
         proxy.happy-eyeballs.connection-attempt-delay: 1000
EOT
});

sleep 1; # inject some delay, as the following tests are a bit time-sensitive

foreach_http(sub {
    my ($scheme, $port, @opts) = @_;
    my $check_access = sub {
        my ($host, $expected_resp, $expected_time) = @_;
        my $start_at = time;
        my ($rfh, $wfh);
        pipe $rfh, $wfh
            or die "pipe failed:$!";
        my $pid = fork;
        die "fork failed:$!"
            unless defined $pid;
        if ($pid == 0) {
            # child process
            close $rfh;
            # STDIN is changed to an ever-open pipe so that h2o-httpclient would read all data without sending anything)
            my $fh = do {
                local $^F = 255; # don't set O_CLOEXEC on $fh
                pipe STDIN, my $fh
                    or die "pipe failed:$!";
                $fh;
            };
            open STDOUT, ">&", $wfh
                or die "failed to redirect STDERR:$!";
            open STDERR, ">&", $wfh
                or die "failed to redirect STDERR:$!";
            exec $client_prog, "-k", @opts, qw(-m CONNECT -x), "$scheme://127.0.0.1:$port", "$host.inject.example.com:80";
            die "failed to launch $client_prog:$!";
        }
        close $wfh;
        like do { local $/; <$rfh> }, qr{^HTTP/[0-9\.]+ 200.*\n\n$expected_resp$}s;
        my $elapsed = time - $start_at;
        note "elapsed: $elapsed";
        cmp_ok $elapsed, ">=", $expected_time->[0];
        cmp_ok $elapsed, "<=", $expected_time->[1];
    };
    subtest "one v4" => sub {
        $check_access->("p$v4_port.4127-0-0-1", "127.0.0.1", [0, 0.5]);
    };
    subtest "one v6" => sub {
        $check_access->("p$v6_port.6--1", "::1", [0, 0.5]);
    };
    subtest "v6 -> v4" => sub {
        $check_access->("p$v6_port.6--1.d100.p$v4_port.4127-0-0-1", "::1", [0, 0.5]);
    };
    subtest "v4 -> v6" => sub {
        $check_access->("p$v4_port.4127-0-0-1.d250.p$v6_port.6--1", "::1", [0.25, 0.75]);
    };
    subtest "v4 -> name-resolution-delay -> v6" => sub {
        $check_access->("p$v4_port.4127-0-0-1.d600.p$v6_port.6--1", "127.0.0.1", [0.5, 1]);
    };
    my $blackhole_ipv4_dash = $blackhole_ip_v4;
    $blackhole_ipv4_dash =~ tr/./-/;
    subtest "v4-blackhole -> v4" => sub {
        $check_access->("4$blackhole_ipv4_dash.p$v4_port.4127-0-0-1", "127.0.0.1", [1, 2]);
    };
    subtest "v4-blackhole -> v6" => sub {
        $check_access->("4$blackhole_ipv4_dash.p$v4_port.4127-0-0-1.d600.p$v6_port.6--1", "::1", [1, 2]);
    };
});

undef $server;

done_testing;

sub create_listener {
    my $localhost = shift;
    my $listener = IO::Socket::IP->new(
        LocalHost => $localhost,
        LocalPort => 0,
        Type => SOCK_STREAM,
        Listen => 5,
    ) or return;
    my $pid = fork;
    die "fork failed:$pid"
        unless defined $pid;
    if ($pid == 0) {
        while (my $sock = $listener->accept) {
            $sock->syswrite($localhost);
        }
        exit 0;
    }
    +(
        make_guard(sub { kill 'KILL', $pid }),
        $listener->sockport,
    );
}

sub foreach_http {
    my $cb = shift;
    for (['h1', 'http', $server->{port}], ['h1s', 'https', $server->{tls_port}], ['h3', 'https', $quic_port, qw(-3 100)]) {
        subtest shift(@$_) => sub {
            $cb->(@$_);
        };
    }
}
