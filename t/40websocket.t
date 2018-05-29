use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

# spawn upstream
my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

sub silent_server {
    return spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
        proxy.websocket: ON
        proxy.websocket.timeout: 1000
EOT
}

subtest "http/1.1" => sub {
    my $server = silent_server();
    plan skip_all => "curl not found"
        unless prog_exists("curl");
    my $resp = `curl --silent --insecure 'http://127.0.0.1:$server->{port}/index.txt'`;
    is $resp, "hello\n";
};

sub doit {
    my $conn = shift;
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
    for my $i (1..10) {
        my $msg = "hello world $i\n";
        is $conn->syswrite($msg), length($msg), "write text ($i)";
        is $conn->sysread($rbuf, 65536), length($msg), "read echo ($i)";
        is $rbuf, $msg, "echo is correct ($i)";
    }
    $conn->close;
}

subtest "ws" => sub {
    my $server = silent_server();
    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    doit($conn);
};

subtest "wss" => sub {
    my $server = silent_server();
    eval q{use IO::Socket::SSL; 1}
        or plan skip_all => "IO::Socket::SSL not found";
    my $conn = IO::Socket::SSL->new(
        PeerAddr        => "127.0.0.1:$server->{tls_port}",
        SSL_verify_mode => 0,
    ) or die "failed to connect via TLS to 127.0.0.1:$server->{tls_port}:". IO::Socket::SSL::errstr();
    doit($conn);
};

subtest "logged-ws" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
        proxy.websocket: ON
        proxy.websocket.timeout: 1000
access-log: /dev/null # enable logging
EOT

    my $conn = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $server->{port},
        Proto    => 'tcp',
    ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
    doit($conn);
};

subtest 'upon http2' => sub {
    my $code = sub {
        my ($server, $path) = @_;
        return <<"EOR";
        req = {
            ":method" => "CONNECT",
            ":authority" => "127.0.0.1:$server->{port}",
            ":scheme" => "http",
            ":path" => "$path",
            ":protocol" => "websocket",
        }
        h2g.send_headers(req, 1, END_HEADERS | END_STREAM)

        sender = proc {
            index = 0
            lambda {
                if index == 5
                    h2g.send_data(1, END_STREAM, '')
                    return false
                end
                index += 1
                h2g.send_data(1, 0, "data #{index}")
                true
            }
        }.call

        loop do
            f = h2g.read
            if f == nil
                puts "timeout"
                exit 1
            end
            puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
            if f.type == 'HEADERS'
              puts f.to_s
              if f.flags & END_HEADERS
                break unless sender.call
              end
            elsif f.type == 'DATA'
              break unless sender.call
            elsif f.type == 'RST_STREAM' || f.type == 'GOAWAY'
              break
            end
        end
EOR
    };
    subtest 'basic' => sub {
        my $server = silent_server();
        my $output = run_with_h2get_simple($server, $code->($server, '/websocket'));
        like $output, qr{':status' => '200'}i;
        unlike $output, qr{sec-websocket-accept}i;
        unlike $output, qr{RST_STREAM|GOAWAY};
        my @m = $output =~ m/DATA, stream_id:1, len:6, flags:0/g;
        is scalar(@m), 5
    };
    subtest 'invalid accept key' => sub {
        my $server = silent_server();
        my $output = run_with_h2get_simple($server, $code);
        my $output = run_with_h2get_simple($server, $code->($server, '/websocket?invalid_accept_key'));
        like $output, qr{':status' => '502'}i;
    };
};

done_testing;
