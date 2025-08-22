# This test makes sure that there is limit in the amount of buffer used by a CONNECT tunnel, by running a server that echoes the
# input using 1KB buffer, and by running a client that sends data through the tunnel without reading the response.

use strict;
use warnings;
use Errno qw(EAGAIN EINTR EWOULDBLOCK);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use IO::Select;
use IO::Socket::INET;
use IPC::Open3;
use Scope::Guard;
use Socket qw(IPPROTO_TCP TCP_NODELAY);
use Symbol qw(gensym);
use Time::HiRes qw(sleep);
use Test::More;
use Net::EmptyPort qw(check_port);
use t::Util;

local $SIG{PIPE} = sub {};

my $origin_port = empty_port();

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $server = spawn_h2o(<< "EOT");
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
          - "+127.0.0.1:$origin_port"
        proxy.timeout.io: 10000
EOT

# setup a server that echoes the input using buffer size of 1KB
my $origin_guard = do {
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
        while (1) {
            if (my $sock = $listener->accept) {
                if (!defined setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, 1)) {
                    die "setsockopt(TCP_NODELAY) failed:$!";
                }
                while (sysread($sock, my $buf, 1024) > 0) {
                    while (length $buf != 0) {
                        my $ret = syswrite($sock, $buf, length $buf);
                        last unless $ret > 0;
                        substr $buf, 0, $ret, "";
                    }
                }
            }
        }
        die "unreachable";
    }
    # parent process
    undef $listener;
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
    my $req = "CONNECT 127.0.0.1:$origin_port HTTP/1.1\r\n\r\n";
    subtest "establish-tunnel" => sub {
        is syswrite($sock, $req), length $req, "send request";
        sysread $sock, my $resp, 1024;
        like $resp, qr{HTTP/1\.1 200 .*\r\n\r\n$}s, "got 200 response";
    };
    test_tunnel($sock, $sock, undef);
};

subtest "h2o-httpclient" => sub {
    my $client_prog = bindir() . "/h2o-httpclient";
    plan skip_all => "$client_prog not found"
        unless -e $client_prog;
    for (['h1', 'http', $server->{port}, ''], ['h1s', 'https', $server->{tls_port}, ''], ['h3', 'https', $quic_port, '-3 100']) {
        my ($name, $scheme, $port, $opts) = @$_;
        subtest $name => sub {
            # open client
            my ($writefh, $readfh, $errfh);
            $errfh = gensym;
            my $guard = do {
                my $pid = open3($writefh, $readfh, $errfh, "exec $client_prog -k $opts -m CONNECT -x $scheme://127.0.0.1:$port 127.0.0.1:$origin_port");
                die unless $pid > 0;
                sub {
                    kill 'KILL', $pid;
                    while (waitpid($pid, 0) != $pid) {}
                };
            };
            # check if tunnel is established
            my $resp = read_until_blocked($errfh);
            like $resp, qr{HTTP/\S+ 200.*\n\n$}s, "got 200 response";
            test_tunnel($writefh, $readfh, $errfh);
        };
    }
};

done_testing;

sub test_tunnel {
    my ($writefh, $readfh, $errfh) = @_;
    subtest "test-echo" => sub {
        is syswrite($writefh, "hello\n"), 6;
        my $resp = read_until_blocked($readfh);
        is $resp, "hello\n";
    };
    my $all_read = '';
    my @all_lengths_written;
    for my $ch (1..5) {
        subtest "run $ch" => sub {
            my $bytes_written;
            subtest "write-much-as-possible" => sub {
                $bytes_written = write_until_blocked($writefh, $ch);
                die "unexpected close during write:" . ($errfh ? read_until_blocked($errfh) : "")
                    unless defined $bytes_written;
                diag "stall after $bytes_written bytes";
                pass "stalled";
                push @all_lengths_written, $bytes_written;
            };
            subtest "read-all" => sub {
                my $buf = read_until_blocked($readfh);
                is length $buf, $bytes_written;
                $all_read .= $buf;
            };
        };
    }
    my @all_lengths_read;
    for my $ch (1..5) {
        if ($all_read =~ /^($ch*)/s) {
            push @all_lengths_read, length $1;
            $all_read = $';
        } else {
            push @all_lengths_read, 0;
        }
    }
    subtest "byte pattern" => sub {
        is_deeply \@all_lengths_read, \@all_lengths_written, "lengths of each block";
        is $all_read, '', "nothing excess";
    };
}

sub write_until_blocked {
    my ($sock, $ch) = @_;
    my $bytes_written = 0;

    fcntl $sock, F_SETFL, O_NONBLOCK
        or die "failed to set O_NONBLOCK:$!";

    while (1) {
        my $ret = syswrite $sock, $ch x 65536;
        if (defined $ret) {
            return undef if $ret == 0;
            # continue writing
            $bytes_written += $ret;
        } else {
            if ($! == EAGAIN || $! == EWOULDBLOCK) {
                # wait for max 0.5 seconds (see read_until_blocked for rationale)
                last if !IO::Select->new([ $sock ])->can_write(0.5);
            } elsif ($! == EINTR) {
                # retry
            } else {
                return undef;
            }
        }
    }

    fcntl $sock, F_SETFL, 0
        or die "failed to clear O_NONBLOCK:$!";

    return $bytes_written;
}

sub read_until_blocked {
    my $sock = shift;

    fcntl $sock, F_SETFL, O_NONBLOCK
        or die "failed to set O_NONBLOCK:$!";

    my $buf = '';
    while (1) {
        my $ret = sysread $sock, $buf, 65536, length $buf;
        if (defined $ret) {
            if ($ret > 0) {
                # continue reading
            } else {
                # EOF
                last;
            }
        } else {
            if ($! == EAGAIN || $! == EWOULDBLOCK) {
                # Wait for max. 2 seconds for additional data. Due to `h2o-httpclient` using blocked write to emit what is being
                # received, this timeout should be more than 2x greater than that of `write_until_blocked`. That is because the
                # cause of write stall is the blocked write, which could keep the QUIC stack within `h2o-httpclient` in an
                # unresponsive state for the timeout specified in `write_until_blocked` (0.5 seconds). That would lead to h2o
                # sending multiple PTO probes doing an exponential back-off by 2x for 0.5 seconds. Hence 1 second is the minimum
                # here. We use 2 seconds to be on the safe side (TODO: use non-blocking write in `h2o-httpclient`).
                $! = 0;
                if (!IO::Select->new([ $sock ])->can_read(2)) {
                    last unless $!; # timeout
                }
            } elsif ($! == EINTR) {
                # retry
            } else {
                # error
                last;
            }
        }
    }

    fcntl $sock, F_SETFL, 0
        or die "failed to clear O_NONBLOCK:$!";

    $buf;
}
