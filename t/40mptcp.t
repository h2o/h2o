use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use Errno qw(EINTR);
use Socket qw(SOL_SOCKET SO_PROTOCOL SOCK_STREAM IPPROTO_TCP);
use t::Util;

# IPPROTO_MPTCP is defined as 262 in include/uapi/linux/in.h
use constant IPPROTO_MPTCP => 262;

# TCP_IS_MPTCP is defined as 43 in include/uapi/linux/tcp.h
use constant TCP_IS_MPTCP => 43;

my $mptcp_enabled = -f '/proc/sys/net/mptcp/enabled' && `cat /proc/sys/net/mptcp/enabled` + 0 > 0;
plan skip_all => 'MPTCP not enabled on this system' unless $mptcp_enabled;

plan 'skip_all' => 'H2O not built with MPTCP' unless server_features()->{mptcp};

my $mptcp_working = check_mptcp();
plan skip_all => 'MPTCP not working on this system' unless $mptcp_working;

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

sub check_mptcp {
    my $serv_sock = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1",
        LocalPort => 0,
        Proto    => IPPROTO_MPTCP,
        Type     => SOCK_STREAM,
        Listen   => 5,
    );
    unless ($serv_sock) {
        return;
    }

    my $client_sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => $serv_sock->sockport(),
        Proto    => IPPROTO_MPTCP,
        Type     => SOCK_STREAM,
    );
    unless ($client_sock) {
        return;
    }

    my $is_mptcp = is_socket_mptcp($client_sock) or return;

    close $client_sock;
    close $serv_sock;

    return $is_mptcp;
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
