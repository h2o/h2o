use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use File::Temp qw(tempfile);
use IO::Socket::SSL;
BEGIN { $ENV{HTTP2_DEBUG} = 'debug' }
use Protocol::HTTP2::Constants qw(:frame_types :errors :settings :flags :states :limits :endpoints);
use Protocol::HTTP2::Connection;
use Scope::Guard;
use t::Util;
$|=1;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'basic' => sub {
    my $upstream_port = $ENV{UPSTREAM_PORT} || empty_port({ host => '0.0.0.0' });
    my $upstream = create_upstream($upstream_port, +{
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
    my $upstream = create_upstream($upstream_port, +{
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
    my $upstream = create_upstream($upstream_port, +{
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
    my $upstream = create_upstream($upstream_port, +{
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
    my $log = $upstream->{read_all}->();
    like $log, qr{Receive reset stream with error code CANCEL};
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

sub create_upstream {
    my ($upstream_port, $stream_state_cbs, $stream_frame_cbs) = @_;

    my ($cout, $pin);
    pipe($pin, $cout);

    my $pid = fork;
    if ($pid) {
        close $cout;
        my $upstream; $upstream = +{
            pid => $pid,
            kill => sub {
                return unless defined $pid;
                kill 'KILL', $pid;
                undef $pid;
            },
            guard => Scope::Guard->new(sub {
                $upstream->{kill}->()
            }),
            read => sub {
                my $line = <$pin>;
                return $line;
            },
            read_all => sub {
                join('', <$pin>);
            },
        };
        return $upstream;
    }
    close $pin;
    open(STDOUT, '>&=', fileno($cout)) or die $!;
    my $conn; $conn = Protocol::HTTP2::Connection->new(SERVER,
        on_new_peer_stream => sub {
            my $stream_id = shift;
            for my $state (keys %{ $stream_state_cbs || +{} }) {
                my $cb = $stream_state_cbs->{$state};
                $conn->stream_cb($stream_id, $state, sub {
                    $cb->($conn, $stream_id);
                });
            }
            for my $type (keys %{ $stream_frame_cbs || +{} }) {
                my $cb = $stream_frame_cbs->{$type};
                $conn->stream_frame_cb($stream_id, $type, sub {
                    $cb->($conn, $stream_id, shift);
                });
            }
        },
    );
    my $upstream = IO::Socket::SSL->new(
        LocalAddr => '127.0.0.1',
        LocalPort => $upstream_port,
        Listen => 1,
        ReuseAddr => 1,
        SSL_cert_file => 'examples/h2o/server.crt',
        SSL_key_file => 'examples/h2o/server.key',
        SSL_alpn_protocols => ['h2'],
    ) or die "cannot create socket: $!";
    my $sock = $upstream->accept;

    my $input = '';

    while (1) {
        my $offset = 0;
        my $buf;
        next unless $sock->read($buf, 1);
        $input .= $buf;

        unless ($conn->preface) {
            my $len = $conn->preface_decode(\$input, 0);
            unless (defined($len)) {
                die 'invalid preface';
            }
            next unless $len;
            $conn->preface(1);
            $offset += $len;
        }

        while (my $len = $conn->frame_decode(\$input, $offset)) {
            $offset += $len;
        }
        substr($input, 0, $offset) = '' if $offset;

        while (my $frame = $conn->dequeue) {
            $sock->write($frame);
        }
    }
    exit;
}

done_testing();
