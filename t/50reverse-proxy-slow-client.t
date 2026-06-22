use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Socket::UNIX;
use File::Temp qw(tempdir);
use POSIX qw(WNOHANG);
use Test::More;
use Time::HiRes qw(sleep time);
use t::Util;

my $body_size = 20 * 1024 * 1024;

sub spawn_large_response_upstream {
    my ($socket_path, $body_size) = @_;
    my $server = IO::Socket::UNIX->new(
        Type   => SOCK_STREAM,
        Local  => $socket_path,
        Listen => 1,
    ) or die "failed to listen to $socket_path:$!";

    my $pid = fork;
    die "fork failed:$!" unless defined $pid;

    if ($pid != 0) {
        close $server;
        return make_guard(sub {
            kill "KILL", $pid;
            while (waitpid($pid, WNOHANG) != $pid) {}
            unlink $socket_path;
        });
    }

    $SIG{PIPE} = "IGNORE";
    while (my $sock = $server->accept) {
        my $req = "";
        while ($req !~ /\r\n\r\n/s) {
            my $r = sysread $sock, my $buf, 8192;
            last unless $r;
            $req .= $buf;
        }

        syswrite $sock, "HTTP/1.1 200 OK\r\nContent-Length: $body_size\r\nConnection: close\r\n\r\n";
        my $chunk = "0" x 65536;
        for (my $sent = 0; $sent < $body_size;) {
            my $len = $body_size - $sent < length($chunk) ? $body_size - $sent : length($chunk);
            my $w = syswrite $sock, $chunk, $len;
            last unless defined $w && $w != 0;
            $sent += $w;
        }
        close $sock;
    }
    exit 0;
}

sub run_slow_client {
    my ($proto, $port) = @_;

    my $sock = $proto eq "https" ? IO::Socket::SSL->new(
        PeerHost => "127.0.0.1",
        PeerPort => $port,
        Proto    => "tcp",
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        SSL_alpn_protocols => [ "http/1.1" ],
    ) : IO::Socket::INET->new(
        PeerHost => "127.0.0.1",
        PeerPort => $port,
        Proto    => "tcp",
    );
    die "failed to connect to h2o:$!" unless $sock;

    print $sock "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    my $received = "";
    my $start_at = time;
    my $bytes_per_sec = $ENV{SLOW_CLIENT_BYTES_PER_SEC} || 1024 * 1024;
    while (1) {
        my $r = sysread $sock, my $buf, 8192;
        last unless $r;
        $received .= $buf;
        my $target_elapsed = length($received) / $bytes_per_sec;
        my $sleep_for = $target_elapsed - (time - $start_at);
        sleep $sleep_for if $sleep_for > 0;
    }
    my $elapsed = time - $start_at;

    like $received, qr{^HTTP/1\.1 200\b}s, "$proto: received response headers";
    my ($headers, $body) = split /\r\n\r\n/, $received, 2;
    diag "$proto: received @{[ length($body) ]} of $body_size bytes in ${elapsed}s";
    is length($body), $body_size, "$proto: response body was not truncated by http1 request I/O timeout";
}

my $tempdir = tempdir(CLEANUP => 1);
my $upstream_socket = "$tempdir/upstream.sock";
my $upstream_guard = spawn_large_response_upstream($upstream_socket, $body_size);

my $server = spawn_h2o(<< "EOT");
http1-request-io-timeout: 1
proxy.zerocopy: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://[unix:$upstream_socket]/
        proxy.timeout.io: 1000000
EOT

subtest "http" => sub {
    run_slow_client("http", $server->{port});
};

subtest "https" => sub {
    run_slow_client("https", $server->{tls_port});
};

done_testing();
