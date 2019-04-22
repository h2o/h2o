use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
BEGIN { $ENV{HTTP2_DEBUG} = 'debug' }
use Protocol::HTTP2::Constants qw(:frame_types :errors :settings :flags :states :limits :endpoints);
use Scope::Guard;
use t::Util;
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
    like $body, qr/upstream error \(connection level\)/;
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

    $upstream->{kill}->();
    my $log = join('', readline($upstream->{stdout}));
    like $log, qr{Receive reset stream with error code CANCEL};
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
    my $output = run_with_h2get_simple($server, <<"EOR");
        req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/" }
        h2g.send_headers(req, 1, END_HEADERS)
        h2g.send_data(1, 0, "a")
        sleep 1
        h2g.send_data(1, END_STREAM, "a" * 1024)
        h2g.read_loop(100)
EOR
    $upstream->{kill}->();
    my $log = join('', readline($upstream->{stdout}));
    like $log, qr{TYPE = DATA\(0\), FLAGS = 00000000, STREAM_ID = 1, LENGTH = 1};
    like $log, qr{TYPE = DATA\(0\), FLAGS = 00000001, STREAM_ID = 1, LENGTH = 1024};
};

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
EOT
    return $server;
}

done_testing();
