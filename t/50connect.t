use strict;
use warnings;
use File::Temp qw(tempdir);
use Time::HiRes qw(sleep);
use Test::More;
use Net::EmptyPort qw(check_port);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $origin_port = empty_port();
my $origin = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $origin_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($origin_port);
    },
);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $one_shot_upstream = empty_port();
my $g2 = one_shot_http_upstream("It works!", $one_shot_upstream);
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
          - "+127.0.0.1:$one_shot_upstream"
          - "+255.255.255.255:$origin_port"
        proxy.timeout.io: 2000
EOT

my $ok_resp = qr{HTTP/[^ ]+ 200\s}m;

subtest "h2get-connect" => sub {
    my ($stderr,$stdout) = run_with_h2get_simple($server, <<"EOS");
    req = {
        ":method" => "CONNECT",
        ":authority" => "127.0.0.1:$one_shot_upstream",
    }
    h2g.send_headers(req, 1, END_HEADERS)
    while true
        f = h2g.read(-1)
        if f.type == "WINDOW_UPDATE" then
            next
        elsif f.type == "HEADERS" then
            break
        else
            puts "got #{f.type} failed"
            exit 1
        end
    end
    h2g.send_data(1, 0, "It doesn't have to be HTTP!")
    f = h2g.read(-1)
    puts f.payload
    if f.type != "DATA" then
        puts "Frame type failed"
    end
    f = h2g.read(-1)
    if f.type != "DATA" then
        puts "Frame type failed"
    end
EOS
    like $stdout, qr/It works!/s, "Response from origin";
    unlike $stdout, qr/Failed/s, "Received expected frames";
};

subtest "curl-h1" => sub {
    my $re_success = qr{Proxy replied 200 to CONNECT request|CONNECT tunnel established, response 200}m;
    my $re_fail = sub {
        my $code = shift;
        qr{Received HTTP code $code from proxy after CONNECT|CONNECT tunnel failed, response $code}m;
    };
    subtest "basic", sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/echo 2>&1`;
        like $content, $re_success, "Connect got a 200 response to CONNECT";
        my @c = $content =~ /$ok_resp/g;
        is @c, 2, "Got two 200 responses";
        unlike $content, qr{proxy-status:}i;
    };
    subtest "timeout", sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/sleep-and-respond?sleep=1 2>&1`;
        like $content, $re_success, "Connect got a 200";
        my @c = $content =~ /$ok_resp/g;
        is @c, 2, "Got two 200 responses, no timeout";
        unlike $content, qr{proxy-status:}i;

        $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/sleep-and-respond?sleep=10 2>&1`;
        like $content, $re_success, "Connect got a 200";
        @c = $content =~ /$ok_resp/g;
        is @c, 1, "Only got one 200 response";
        unlike $content, qr{proxy-status:}i;
    };
    subtest "acl" => sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error https://8.8.8.8/ 2>&1 2>&1`;
        like $content, $re_fail->(403);
        unlike $content, qr{proxy-status:}i;
    };
    subtest "immediate connect failure" => sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://255.255.255.255:$origin_port/ 2>&1 2>&1`;
        like $content, $re_fail->(502);
    };
};

subtest "h2o-httpclient" => sub {
    my $client_prog = bindir() . "/h2o-httpclient";
    plan skip_all => "$client_prog not found"
        unless -e $client_prog;
    my $connect_get_resp = sub {
        my ($scheme, $port, $opts, $target, $send_cb) = @_;
        open my $fh, "|-", "exec $client_prog -k $opts -m CONNECT -x $scheme://127.0.0.1:$port/ $target > $tempdir/out 2> $tempdir/err"
            or die "failed to launch $client_prog:$!";
        $fh->autoflush(1);
        $send_cb->($fh);
        close $fh;
        open $fh, "<", "$tempdir/out"
            or die "failed to open $tempdir/out:$!";
        do { local $/; <$fh> };
    };
    for (['h1', 'http', $server->{port}, ''],
         ['h1s', 'https', $server->{tls_port}, ''],
         ['h2', 'https', $server->{tls_port}, '-2 100'],
         ['h3', 'https', $quic_port, '-3 100']) {
        my ($name, $scheme, $port, $opts) = @$_;
        subtest $name => sub {
            subtest "basic" => sub {
                my $resp = $connect_get_resp->($scheme, $port, $opts, "127.0.0.1:$origin_port", sub {
                    my $fh = shift;
                    sleep 0.5;
                    print $fh "GET /index.txt HTTP/1.0\r\n\r\n";
                    sleep 0.5;
                });
                like $resp, qr{^HTTP/1.1 200 OK\r\n.*?\r\n\r\nhello\n$}s;
            };
            subtest "early" => sub {
                my $resp = $connect_get_resp->($scheme, $port, $opts, "127.0.0.1:$origin_port", sub {
                    my $fh = shift;
                    print $fh "GET /index.txt HTTP/1.0\r\n\r\n";
                    sleep 0.5;
                });
                like $resp, qr{^HTTP/1.1 200 OK\r\n.*?\r\n\r\nhello\n$}s;
            };
        };
    }
};

subtest "port-range-acl" => sub {
    plan skip_all => "curl not found"
        unless prog_exists("curl");

    # Spawn 2 more origin servers and then
    # Spawn a second h2o with a port-range ACL that allows 2 and not the third
    my $origin_port2 = empty_port();
    my $origin2 = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null -p), $origin_port2, ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($origin_port2);
        },
    );

    my $origin_port3 = empty_port();
    my $origin3 = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null -p), $origin_port3, ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($origin_port3);
        },
    );

    my ($port_min, $port_max, $port_disallowed) = sort { $a <=> $b } ($origin_port, $origin_port2, $origin_port3);

    my $server2 = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+127.0.0.0/8:$port_min-$port_max"
          - "-*"
EOT

    my $curl_success = qr{Proxy replied 200 to CONNECT request|CONNECT tunnel established, response 200}m;
    my $curl_fail_403 = qr{Received HTTP code 403 from proxy after CONNECT|CONNECT tunnel failed, response 403}m;

    subtest "within range - allowed" => sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server2->{port} --silent -v --show-error http://127.0.0.1:$port_min/echo 2>&1`;
        like $content, $curl_success, "port in range accepted";

        my $content2 = `curl --http1.1 -p -x 127.0.0.1:$server2->{port} --silent -v --show-error http://127.0.0.1:$port_max/echo 2>&1`;
        like $content2, $curl_success, "port in range accepted";
    };
    subtest "outside range - rejected" => sub {
        my $content = `curl --http1.1 -p -x 127.0.0.1:$server2->{port} --silent -v --show-error http://127.0.0.1:$port_disallowed/echo 2>&1`;
        like $content, $curl_fail_403, "port outside range rejected";
    };
};

done_testing;
