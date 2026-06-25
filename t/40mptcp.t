use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use Errno qw(EINTR);
use Socket qw(SOCK_STREAM IPPROTO_TCP);
use t::Util;

plan 'skip_all' => 'MPTCP test uses hard-coded values for socket constants and therefore rely on linux'
    unless $^O eq 'linux';
use constant IPPROTO_MPTCP => 262;
use constant TCP_IS_MPTCP => 43;

plan 'skip_all' => 'H2O not built with MPTCP'
    unless server_features()->{mptcp};

plan skip_all => 'MPTCP not working on this system'
    unless mptcp_works();

my ($port) = empty_ports(1, { host => "127.0.0.1" });

my $server = spawn_h2o_raw(<< "EOT", [$port]);
listen:
  host: 127.0.0.1
  port: $port
  type: mptcp
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

subtest "client socket" => sub {
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => $port,
        Proto    => IPPROTO_MPTCP,
        Type     => SOCK_STREAM,
    );
    unless ($sock) {
        fail("Failed to connect to server: $!");
        return;
    }
    pass("Connected to server");

    ok(is_socket_mptcp($sock), "Socket protocol is MPTCP");

    my $data = "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n";
    write_all($sock, $data) == length($data) or die "failed to send data:$!";

    my $resp = read_all($sock);
    like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s, "Response ok";

    close $sock;
};

undef $server;

done_testing;

sub mptcp_works {
    my $listener_sock = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1",
        LocalPort => 0,
        Proto    => IPPROTO_MPTCP,
        Type     => SOCK_STREAM,
        Listen   => 5,
    ) or return;
    my $client_sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => $listener_sock->sockport(),
        Proto    => IPPROTO_MPTCP,
        Type     => SOCK_STREAM,
    ) or return;

    my $server_sock = $listener_sock->accept() or return;

    return is_socket_mptcp($client_sock) && is_socket_mptcp($server_sock);
}

sub is_socket_mptcp {
    my $sock = shift;

    my $packed = getsockopt($sock, IPPROTO_TCP, TCP_IS_MPTCP) or return;

    return unpack("I", $packed);
}

sub write_all {
    my ($fh, $buf) = @_;

    my $bytes_left = length($buf);
    my $offset = 0;

    while ($bytes_left > 0) {
        my $written = syswrite($fh, $buf, $bytes_left, $offset);
        if (!defined $written) {
            next if $! == EINTR;
            return;
        }

        if ($written == 0) {
            $! = 0;
            return $offset;
        }

        $bytes_left -= $written;
        $offset += $written;
    }

    return $offset;
}

sub read_all {
    my $fh = shift;
    my $resp = '';
    while (sysread($fh, $resp, 65536, length($resp))) {}
    return $resp;
}
