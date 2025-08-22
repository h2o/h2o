use strict;
use warnings;
use Errno qw(EAGAIN EINTR EWOULDBLOCK);
use Fcntl qw(F_SETFL O_NONBLOCK);
use IO::Select;
use IO::Socket::INET;
use Scope::Guard;
use Socket qw(IPPROTO_TCP TCP_NODELAY);
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;

local $SIG{PIPE} = sub {};

my $origin_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+127.0.0.1:$origin_port"
        proxy.timeout.io: 5000
      "/ruok":
        file.file: t/assets/doc_root/alice.txt
EOT

pipe(my $sync_read, my $sync_write)
    or die "pipe failed:$!";

my $tcp_origin_guard = do {
    my $listener = IO::Socket::INET->new(
        Listen    => 5,
        LocalAddr => "127.0.0.1:$origin_port",
        Proto     => "tcp",
    ) or die "failed to open listener:$!";
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # child process
        my @sockets;
        while (1) {
            if (my $sock = $listener->accept) {
                write_until_blocked($sock);
                # Tell the client side of the test that we are done filling the pipe.
                syswrite($sync_write, 'x', 1) == 1
                    or die "sync pipe write failed:$!";
                # Keep the socket open.
                push @sockets, $sock;
            }
        }
        die "unreachable";
    }
    # parent process
    Scope::Guard->new(sub {
        kill 'KILL', $pid;
        while (waitpid($pid, 0) != $pid) {}
    });
};

subtest "handwritten-h1-client" => sub {
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server->{port}",
        Proto    => "tcp",
    ) or die "failed to connect to server:$!";
    subtest "establish-tunnel" => sub {
        my $req = "CONNECT 127.0.0.1:$origin_port HTTP/1.1\r\n\r\n";
        is syswrite($sock, $req), length $req, "send request";
        sysread $sock, my $resp, 1024;
        like $resp, qr{^HTTP/1\.1 200}s, "got 200 response"
            or BAIL_OUT;
    };
    subtest "fill-up-read-pipe" => sub {
        is sysread($sync_read, my $buf, 1), 1;
    };
    # The writes incidentally re-arm the io-timeout.
    diag "fill-up-write-pipe";
    write_until_blocked($sock);
    diag "wait-for-io-timeout";
    sleep 6;
    subtest "is-h2o-ok" => sub {
        my $sock2 = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$server->{port}",
            Proto    => "tcp",
        );
        ok $sock2, "connect to server";
        my $req = "GET /ruok HTTP/1.1\r\n\r\n";
        is syswrite($sock2, $req), length $req, "send request";
        sysread $sock2, my $resp, 1024;
        like $resp, qr{^HTTP/1\.1 200}s, "got 200 response";
    };
};

done_testing;

sub write_until_blocked {
    my $sock = shift;
    fcntl($sock, F_SETFL, O_NONBLOCK)
        or die "failed to set O_NONBLOCK:$!";
    setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, 1)
        or die "setsockopt(TCP_NODELAY) failed:$!";
    my $blocked = 0;
    while (1) {
        my $buf = "x" x 65534;
        my $ret = syswrite($sock, $buf, length $buf);
        if (defined($ret)) {
            $blocked = 0;
            next;
        }
        # After the write blocks, sleep a second and try again.
        # If the write keeps blocking then we are done stuffing the pipe.
        if ($! == EAGAIN || $! == EWOULDBLOCK) {
            $! = 0;
            if (!IO::Select->new([ $sock ])->can_write(1)) {
                die "select failed:$!" if $!;
                # timeout
                $blocked += 1;
                last if $blocked >= 2;
            }
        } elsif ($! == EINTR) {
            # retry
            next;
        } else {
            # error
            die "socket write failed:$!";
        }
    }
    fcntl($sock, F_SETFL, 0)
        or die "failed to clear O_NONBLOCK:$!";
}
