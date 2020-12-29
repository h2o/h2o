use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
        proxy.preserve-host: ON
        proxy.tunnel: ON
        proxy.tunnel.timeout: 1000
access-log: /dev/null # enable logging
EOT

sub test_echo {
    my $conn = shift;
    for my $i (1..10) {
        my $msg = "hello world $i\n";
        is $conn->syswrite($msg), length($msg), "write text ($i)";
        is $conn->sysread(my $rbuf, 65536), length($msg), "read echo ($i)";
        is $rbuf, $msg, "echo is correct ($i)";
    }
    $conn->close;
}

sub test_plaintext {
    my $doit = shift;
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    $doit->($conn);
};

sub test_tls {
    my $doit = shift;
    eval q{use IO::Socket::SSL; 1}
        or plan skip_all => "IO::Socket::SSL not found";
    my $conn = IO::Socket::SSL->new(
        PeerAddr        => "127.0.0.1:$server->{tls_port}",
        SSL_verify_mode => 0,
    ) or die "failed to connect via TLS to 127.0.0.1:$server->{tls_port}:". IO::Socket::SSL::errstr();
    $doit->($conn);
};

subtest "websocket" => sub {
    # spawn upstream
    my $upstream = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($upstream_port);
        },
    );

    my $test_get = sub {
        my ($proto, $port) = @_;
        subtest "GET" => sub {
            my $resp = `curl --silent --insecure '$proto://127.0.0.1:$port/index.txt'`;
            is $resp, "hello\n";
        };
    };
    my $test_ws = sub {
        my $conn = shift;
        subtest "websocket" => sub {
            my $req = join(
                "\r\n",
                "GET /websocket/ HTTP/1.1",
                "Connection: upgrade",
                "Upgrade: websocket",
                "Sec-Websocket-Key: abcde",
                "Sec-Websocket-Version: 13",
                "",
                "",
            );
            is $conn->syswrite($req), length($req), "send request";
            $conn->sysread(my $rbuf, 65536) > 0
                or die "failed to read HTTP response";
            like $rbuf, qr{^HTTP\/1\.1 101 }is;
            like $rbuf, qr{\r\n\r\n$}is;
            like $rbuf, qr{\r\nupgrade: websocket\r\n}is;
            unlike $rbuf, qr{\r\nupgrade:.*\r\nupgrade:}is;
            like $rbuf, qr{\r\nsec-websocket-accept: .*\r\n}is;
            test_echo($conn);
        };
    };
    subtest "plaintext" => sub {
        $test_get->('http', $server->{port});
        test_plaintext($test_ws);
    };
    subtest "tls" => sub {
        $test_get->('https', $server->{tls_port});
        test_tls($test_ws);
    };
};

subtest "connect" => sub {
    # create listening socket
    my $server_sock = IO::Socket::INET->new(
        LocalPort => $upstream_port,
        Proto     => "tcp",
        Listen    => 5,
    ) or die "failed to listen to port:$!";
    # fork
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # server
        while (1) {
            # accept
            my $conn = $server_sock->accept
                or next;
            # read request
            $conn->sysread(my $req, 4096)
                or die "failed to read request";
            $req =~ qr{^([^ ]+) ([^ ]+) HTTP/.*?\r\n\r\n(.*)$}s
                or die "failed to parse request";
            die "failed to parse request"
                if $3;
            my ($meth, $origin) = ($1, $2);
            # send 200 and run as an echo server, or send 403
            if ($meth eq 'CONNECT' and $origin !~ /^fail:/) {
                $conn->syswrite("HTTP/1.1 200 OK\r\n\r\n");
                while ($conn->sysread(my $buf, 4096)) {
                    $conn->syswrite($buf)
                        or last;
                }
            } else {
                $conn->syswrite("HTTP/1.1 403 Forbidden\r\ncontent-length: 17\r\n\r\naccess forbidden\n");
            }
        }
    }
    # client; run tests
    undef $server_sock;
    my $test_get = sub {
        my ($proto, $port) = @_;
        subtest "GET" => sub {
            my $resp = `curl --dump-header /dev/stdout --silent --insecure '$proto://127.0.0.1:$port/'`;
            like $resp, qr{^HTTP/[^ ]+ 403.*\naccess forbidden\n$}s;
        };
    };
    my $connect_get_resp = sub {
        my ($conn, $origin) = @_;
        my $req = join "\r\n", "CONNECT $origin HTTP/1.1", "host: $origin", "connection: close", "", "";
        is $conn->syswrite($req), length($req), "send request";
        sleep 0.5; # wait for body
        my $resp = '';
        while (IO::Select->new($conn)->can_read(0)) {
            my $rret = $conn->sysread($resp, 4096, length $resp);
            last if $rret == 0;
            if (! defined $rret) {
                fail "read response";
                return "";
            }
        }
        pass "read response";
        $resp;
    };
    my $test_connect = sub {
        my $connector = shift;
        subtest "fail" => sub {
            $connector->(sub {
                my $conn = shift;
                my $resp = $connect_get_resp->($conn, "fail:8080");
                like $resp, qr{HTTP/[0-9\.]+ 403.*\r\n\r\naccess forbidden\n$}s, "check response";
            });
        };
        subtest "success" => sub {
            $connector->(sub {
                my $conn = shift;
                my $resp = $connect_get_resp->($conn, "success:8080");
                like $resp, qr{HTTP/[0-9\.]+ 200.*\r\n\r\n$}s, "check response";
                test_echo($conn);
            });
        };
    };
    subtest "plaintext" => sub {
        $test_get->('http', $server->{port});
        $test_connect->(\&test_plaintext);
    };
    subtest "tls" => sub {
        $test_get->('https', $server->{tls_port});
        $test_connect->(\&test_tls);
    };
    kill 'KILL', $pid;
    while (waitpid($pid, 0) != $pid) {}
};

done_testing;
