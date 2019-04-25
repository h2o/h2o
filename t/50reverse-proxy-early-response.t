use strict;
use warnings;
use feature qw/say/;
BEGIN { $ENV{HTTP2_DEBUG} = 'debug' }
use Net::EmptyPort qw(check_port empty_port);
use Scope::Guard;
use Test::More;
use Time::HiRes;
use IO::Socket::INET;
use Protocol::HTTP2::Constants qw(:frame_types :errors :settings :flags :states :limits :endpoints);
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

for my $is_h2 (0, 1) {
    my $proto = $is_h2 ? 'h2' : 'h1';
    subtest $proto => sub {
        subtest 'not early response' => sub {
            my $upstream_port = empty_port({ host => '0.0.0.0' });
            my $upstream = create_upstream($upstream_port, $is_h2, +{ wait_body => 1025 });
            my $server = spawn_h2o(h2o_conf($upstream_port, $is_h2));
            my $output = run_with_h2get_simple($server, <<"EOS");
                req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/",
                    "content-length" => "#{1 + 1024}"
                }
                h2g.send_headers(req, 1, END_HEADERS)
                h2g.send_data(1, 0, "a")
                h2g.read_loop(100)
                h2g.send_data(1, END_STREAM, "a" * 1024)
                h2g.read_loop(100)
EOS
            $upstream->{kill}->();
            like $output, qr/HEADERS frame .+':status' => '200'/s;
        };
        subtest 'no_drain_body' => sub {
            my $upstream_port = empty_port({ host => '0.0.0.0' });
            my $upstream = create_upstream($upstream_port, $is_h2);
            my $server = spawn_h2o(h2o_conf($upstream_port, $is_h2));
            my $output = run_with_h2get_simple($server, <<"EOS");
                req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/" }
                h2g.send_headers(req, 1, END_HEADERS)
                h2g.send_data(1, 0, "a")
                h2g.read_loop(100)
                3.times {|n|
                  sleep 1
                  h2g.send_data(1, n == 2 ? END_STREAM : 0, "a" * 1024)
                  if n != 2
                    break if h2g.read_loop(100)
                  end
                }
EOS
            like $output, qr/HEADERS frame .+':status' => '200'/s;
            like $output, qr/RST_STREAM frame/s;
        };

        subtest 'drain_body' => sub {
            plan skip_all => "current h2 testing server implementation cannot test this case" if $is_h2;
            my $upstream_port = empty_port({ host => '0.0.0.0' });
            my $upstream = create_upstream($upstream_port, $is_h2, +{ drain_body => 1 });
            my $server = spawn_h2o(h2o_conf($upstream_port, $is_h2));
            my $output = run_with_h2get_simple($server, <<"EOS");
                req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/",
                    "content-length" => "#{1 + 1024 * 3}" # to avoid chunked encoding
                }
                h2g.send_headers(req, 1, END_HEADERS)
                h2g.send_data(1, 0, "a")
                h2g.read_loop(100)
                3.times {|n|
                  sleep 1
                  h2g.send_data(1, n == 2 ? END_STREAM : 0, "a" * 1024)
                  if n != 2
                    break if h2g.read_loop(100)
                  end
                }
EOS
            like $output, qr/HEADERS frame .+':status' => '200'/s;
            unlike $output, qr/RST_STREAM frame/s;

            if ($is_h2) {
                $upstream->{kill}->();
            } else {
                # issue second request to test that h2o closed the upstream connection
                # (otherwise framing error happens)
                `nghttp -v https://127.0.0.1:$server->{tls_port}`;

                $upstream->{kill}->();
                my $log = join('', readline($upstream->{stdout}));
                like $log, qr/accepted request 2/;
                like $log, qr/received @{[1 + 1024 * 3]} bytes/;
            }
        };

        subtest 'body send error before sending headers' => sub {
            my $upstream_port = empty_port({ host => '0.0.0.0' });
            my $upstream = create_upstream($upstream_port, $is_h2, +{ wait_body => 2, drain_body => 1 });
            my $server = spawn_h2o(h2o_conf($upstream_port, $is_h2));
            local $SIG{ALRM} = sub { $upstream->{kill}->() };
            Time::HiRes::alarm(0.5);
            my $output = run_with_h2get_simple($server, <<"EOS");
                req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/",
                    "content-length" => "#{1 + 1024}" # to avoid chunked encoding
                }
                h2g.send_headers(req, 1, END_HEADERS)
                h2g.send_data(1, 0, "a")
                sleep 1
                h2g.read_loop(100)
EOS
            alarm(0);
            like $output, qr/HEADERS frame .+':status' => '502'/s;
            unlike $output, qr/RST_STREAM frame/s;
        };

        subtest 'body send error after sending headers' => sub {
            my $upstream_port = empty_port({ host => '0.0.0.0' });
            my $upstream = create_upstream($upstream_port, $is_h2, +{ drain_body => 1 });
            my $server = spawn_h2o(h2o_conf($upstream_port, $is_h2));
            local $SIG{ALRM} = sub { $upstream->{kill}->() };
            Time::HiRes::alarm(0.5);
            my $output = run_with_h2get_simple($server, <<"EOS");
                req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/",
                    "content-length" => "#{1 + 1024 * 2}" # to avoid chunked encoding
                }
                h2g.send_headers(req, 1, END_HEADERS)
                h2g.send_data(1, 0, "a")
                h2g.read_loop(100)
                sleep 1
                h2g.send_data(1, 0, "a" * 1024) # second write doesn't cause I/O error..why?
                h2g.send_data(1, 0, "a" * 1024)
                h2g.read_loop(100)
EOS
            alarm(0);
            like $output, qr/HEADERS frame .+':status' => '200'/s;
            like $output, qr/RST_STREAM frame/s;
        };
    };
};

done_testing;

sub h2o_conf {
    my ($upstream_port, $is_h2) = @_;
    my $proto = $is_h2 ? 'https' : 'http';
    return << "EOT";
http2-idle-timeout: 1000000
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /:
        @{[$is_h2 ? 'proxy.http2.ratio: 100' : '' ]}
        proxy.timeout.keepalive: 100000
        proxy.reverse.url: $proto://127.0.0.1:$upstream_port
EOT
}

sub create_upstream {
    my ($upstream_port, $is_h2, $opts) = @_;
    $opts = +{
        drain_body => 0,
        wait_body => 0,
        %{ $opts || +{} }
    };
    if ($is_h2) {
        create_h2_upstream($upstream_port, $opts);
    } else {
        create_h1_upstream($upstream_port, $opts);
    }
}

sub create_h1_upstream {
    my ($upstream_port, $opts) = @_;

    spawn_forked(sub {
        my $server = IO::Socket::INET->new(
            LocalHost => '127.0.0.1',
            LocalPort => $upstream_port,
            Proto => 'tcp',
            Listen => 1,
            Reuse => 1
        );
        my $req = 0;
        while (my $client = $server->accept) {
            say "accepted request @{[++$req]}";
            my $header = '';
            my $body = '';
            my $chunk;
            while ($client->sysread($chunk, 1) > 0) {
                $header .= $chunk;
                if ($header =~ /\r\n\r\n$/) {
                    while (length($body) < $opts->{wait_body}) {
                        if ($client->sysread($chunk, ($opts->{wait_body} - length($body))) > 0) {
                            $body .= $chunk;
                        }
                    }
                    my $content = "hello";
                    $client->syswrite(join("\r\n", (
                        "HTTP/1.1 200 OK",
                        "Content-Length: @{[length($content)]}",
                        "", ""
                    )) . $content);
                    $client->flush;
                    last;
                }
            }
            if ($opts->{drain_body}) {
                while ($client->sysread($chunk, 1024) > 0) {
                    Time::HiRes::sleep(0.0001);
                    $body .= $chunk;
                }
                say "received @{[length($body)]} bytes";
            }
            Time::HiRes::sleep(0.1);
            $client->close;
        }
        $server->close;
    });
}

sub create_h2_upstream {
    my ($upstream_port, $opts) = @_;
    my $upstream;
    my $data_size = 0;
    my $send_headers; $send_headers = sub {
        my ($conn, $stream_id) = @_;
        $conn->send_headers($stream_id, [ ':status' => 200 ], 1);
        unless ($opts->{drain_body}) {
            $conn->{_state}->{closed} = 1;
            $conn->{_state}->{after_write} = sub { Time::HiRes::sleep(0.1) };
        }
        $send_headers = undef;
    };
    $upstream = spawn_h2_server($upstream_port, +{}, +{
        &HEADERS => sub {
            my ($conn, $stream_id, $headers) = @_;
            return unless $send_headers;
            if (!$opts->{wait_body}) {
                $send_headers->($conn, $stream_id);
            }
        },
        &DATA => sub {
            my ($conn, $stream_id, $data) = @_;
            return unless $send_headers;
            if ($opts->{wait_body}) {
                $data_size += length($data);
                if ($data_size >= $opts->{wait_body}) {
                    $send_headers->($conn, $stream_id);
                }
            }
        },
    });
}


