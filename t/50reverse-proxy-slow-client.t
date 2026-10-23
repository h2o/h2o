use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Socket::UNIX;
use File::Temp qw(tempdir);
use POSIX qw(WNOHANG);
use Socket qw(SOL_SOCKET SO_RCVBUF);
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
    setsockopt($sock, SOL_SOCKET, SO_RCVBUF, pack("i", 64 * 1024))
        or die "failed to set SO_RCVBUF:$!";

    print $sock "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    my $received = "";
    my @sleep_at;
    my $bytes_per_sec = 1024 * 1024;
    my $read_unit = 8192;
    my $start_at = time;
    READ:
    while (1) {
        do {
            my $buf = "";
            my $r = sysread $sock, $buf, $read_unit;
            last READ unless $r;
            $received .= $buf;
        } while (length($received) < int((time - $start_at) * $bytes_per_sec));
        push @sleep_at, length($received);
        sleep 0.01;
    }
    my $elapsed = time - $start_at;

    like $received, qr{^HTTP/1\.1 200\b}s, "$proto: received response headers";
    my ($headers, $body) = split /\r\n\r\n/, $received, 2;
    diag "$proto: received @{[ length($body) ]} of $body_size bytes in ${elapsed}s";
    note "$proto: body bytes at sleep: @sleep_at";
    is length($body), $body_size, "$proto: response body was not truncated by http1 request I/O timeout";
}

my $tempdir = tempdir(CLEANUP => 1);
my $upstream_socket = "$tempdir/upstream.sock";
my $upstream_guard = spawn_large_response_upstream($upstream_socket, $body_size);

my ($port, $tls_port) = empty_ports(2, { host => "0.0.0.0" });
my $server = spawn_h2o_raw(<< "EOT", [{ port => $port, proto => "tcp" }, { port => $tls_port, proto => "tcp" }]);
http1-request-io-timeout: 1
proxy.zerocopy: OFF
listen:
  - host: 0.0.0.0
    port: $port
    sndbuf: 65536
  - host: 0.0.0.0
    port: $tls_port
    sndbuf: 65536
    ssl:
      key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://[unix:$upstream_socket]/
        proxy.timeout.io: 1000000
EOT
$server->{port} = $port;
$server->{tls_port} = $tls_port;

subtest "http" => sub {
    run_slow_client("http", $server->{port});
};

subtest "https" => sub {
    run_slow_client("https", $server->{tls_port});
};

done_testing();
