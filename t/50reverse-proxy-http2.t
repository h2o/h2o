use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
BEGIN { $ENV{HTTP2_DEBUG} = 'debug' }
use Protocol::HTTP2::Constants qw(:frame_types :errors :settings :flags :states :limits :endpoints);
use IO::Socket::INET;
use Time::HiRes;
use t::Util;
use JSON;
$|=1;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'basic' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [ ':status' => 200 ], 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl -s --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 200}is;
    ok check_port($server->{port}), 'live check';
};

subtest 'no :status header' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, ['x-foo' => 'bar'], 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl -s --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 502}is;
    like $body, qr/protocol violation/;
    ok check_port($server->{port}), 'live check';
};

subtest 'content-length' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => '11'
            ], 0);
            $conn->send_data($stream_id, 'hello world', 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl -s --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 200}is;
    like $headers, qr{^content-length: 11\r$}im;
    like $body, qr/hello world/;
    ok check_port($server->{port}), 'live check';
};

subtest 'invalid content-length' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => 'foobar'
            ], 0);
            $conn->send_data($stream_id, 'hello world', 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl -s --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 502}is;
    ok check_port($server->{port}), 'live check';

    Time::HiRes::sleep(0.1);
    my ($log) = $upstream->{kill}->();
    like $log, qr{Receive reset stream with error code PROTOCOL_ERROR};
};

subtest 'multiple content-length' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => '7',
                'content-length' => '11',
            ], 0);
            $conn->send_data($stream_id, 'hello world', 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl -s --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 502}is;
    ok check_port($server->{port}), 'live check';

    Time::HiRes::sleep(0.1);
    my ($log) = $upstream->{kill}->();
    like $log, qr{Receive reset stream with error code PROTOCOL_ERROR};
};

subtest 'wrong content-length (too much data)' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => '10'
            ], 0);
            $conn->send_data($stream_id, 'hello', 0);
            $conn->send_data($stream_id, ' world', 1);
        },
    });
    my $server = create_h2o($upstream_port);
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    print $conn "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    my $headers = read_header($conn);
    like $headers, qr{^HTTP/[0-9.]+ 200}is, 'status';
    like $headers, qr{^content-length: 10\r$}im, 'content-length';

    # The http 2 client implementation in h2o raises a protocol error when it
    # receives a data frame that would exceed the remaining content length.
    #
    # The http 2 server in this test sends the response body in two data
    # frames, the first one fits, the second one does not.  The client will
    # receive the content of the first data frame followed by a premature
    # connection closure.
    my $body = read_exactly($conn, 5);
    is $body, "hello", 'body';
    expect_eof($conn);
    close $conn;
};

subtest 'wrong content-length (not enough data)' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => '12'
            ], 0);
            $conn->send_data($stream_id, 'hello world', 1);
        },
    });
    my $server = create_h2o($upstream_port);
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    print $conn "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    my $headers = read_header($conn);
    like $headers, qr{^HTTP/[0-9.]+ 200}is, 'status';
    like $headers, qr{^content-length: 12\r$}im, 'content-length';
    my $body = read_exactly($conn, 11);
    is $body, "hello world", 'body';
    expect_eof($conn);
    close $conn;
};

subtest 'HEAD request with response body' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
                'content-length' => '11'
            ], 0);
            # It is wrong to send a body in response to a HEAD request.
            $conn->send_data($stream_id, 'hello', 0);
            $conn->send_data($stream_id, ' world', 1);
        },
    });
    my $server = create_h2o($upstream_port);
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    print $conn "HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    my $headers = read_header($conn);
    like $headers, qr{^HTTP/[0-9.]+ 200}is, 'status';
    expect_eof($conn);
    close $conn;
};

subtest '204 response with body' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 204
            ], 0);
            # It is wrong to send a body in a status 204 response.
            $conn->send_data($stream_id, 'hello', 0);
            $conn->send_data($stream_id, ' world', 1);
        },
    });
    my $server = create_h2o($upstream_port);
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    print $conn "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    my $headers = read_header($conn);
    like $headers, qr{^HTTP/[0-9.]+ 204}is, 'status';
    expect_eof($conn);
    close $conn;
};

subtest '304 response with body' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 304
            ], 0);
            # It is wrong to send a body in a status 304 response.
            $conn->send_data($stream_id, 'hello', 0);
            $conn->send_data($stream_id, ' world', 1);
        },
    });
    my $server = create_h2o($upstream_port);
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    print $conn "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    my $headers = read_header($conn);
    like $headers, qr{^HTTP/[0-9.]+ 304}is, 'status';
    expect_eof($conn);
    close $conn;
};

subtest 'request body streaming' => sub {
    plan skip_all => "h2get not found"
        unless h2get_exists();
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [
                ':status' => 200,
            ], 0);
            $conn->send_data($stream_id, 'hello world', 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my $streaming_request_count = 3;
    for (my $i=0; $i < $streaming_request_count; $i++) {
        my $output = run_with_h2get_simple($server, <<"        EOR");
            req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/" }
            h2g.send_headers(req, 1, END_HEADERS)
            h2g.send_data(1, 0, "a")
            sleep 1
            h2g.send_data(1, END_STREAM, "a" * 1024)
            h2g.read_loop(100)
        EOR
    }
    my ($log) = $upstream->{kill}->();
    like $log, qr{TYPE = DATA\(0\), FLAGS = 00000000, STREAM_ID = 1, LENGTH = 1};
    like $log, qr{TYPE = DATA\(0\), FLAGS = 00000001, STREAM_ID = 1, LENGTH = 1024};
    my $http2_streaming_requests_str = 'http2.streaming-requests';
    my $resp = `curl --silent http://127.0.0.1:$server->{port}/s/json`;
    my $jresp = decode_json("$resp");
    my $http2_streaming_requests = $jresp->{$http2_streaming_requests_str};
    ok $http2_streaming_requests == $streaming_request_count,
            "Check $http2_streaming_requests_str, " .
            "$http2_streaming_requests == $streaming_request_count"
};

my $test = sub {
    my $opts = shift;

    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = spawn_h2_server($upstream_port, +{
        &HALF_CLOSED => sub {
            my ($conn, $stream_id) = @_;
            $conn->send_headers($stream_id, [ ':status' => 200 ], 1);
        },
    });

    my $server = create_h2o($upstream_port);
    my ($headers, $body) = run_prog("curl --max-time 3 -s --dump-header /dev/stderr $opts http://127.0.0.1:@{[$server->{port}]}");
    like $headers, qr{^HTTP/[0-9.]+ 200}is;
    ok check_port($server->{port}), 'live check';
};

subtest 'POST request with no body, no C-L', sub { $test->('-X POST') };
subtest 'POST request with no body, with C-L:0', sub { $test->("-X POST -d ''") };
subtest 'POST request with body', sub { $test->("-X POST -d a=b") };

sub create_h2o {
    my ($upstream_port) = @_;
    if (my $port = $ENV{H2O_PORT}) {
        return +{ port => $port };
    }
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.ssl.verify-peer: OFF
      /s:
        status: ON
EOT
    return $server;
}

sub read_header {
    my $sock = shift;
    my $hdr = '';
    for (;;) {
        my $line = <$sock>;
        if (!defined($line)) {
            fail "error reading header: $!";
            last;
        }
        last if $line =~ m/^\r?\n$/;
        $hdr .= $line;
    }
    return $hdr;
}

sub read_exactly {
    my $sock = shift;
    my $toread = shift;
    my $res;
    my $nread = read $sock, $res, $toread;

    ok defined($nread), "check for read error";
    is $nread, $toread, "check for partial read";
    return $res;
}

sub expect_eof {
    my $sock = shift;
    my $res = '';
    my $nread = read $sock, $res, 1;
    $nread = 0 unless defined $nread;
    is $nread, 0, "expect end of file (nread=$nread, res='$res')";
}

done_testing();
