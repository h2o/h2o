use strict;
use warnings;
use Test::More;
use Net::EmptyPort qw(check_port);
use t::Util;

my $origin_port = empty_port();
my $origin = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $origin_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($origin_port);
    },
);

my $server = spawn_h2o(<< "EOT");
proxy.proxy-status.identity: "h2o/test"
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+127.0.0.1:$origin_port"
          - "+127.0.0.1:1"
        proxy.connect.emit-proxy-status: ON
EOT

my $ok_resp = qr{HTTP/[^ ]+ 200\s}m;
my $curl_success = qr{Proxy replied 200 to CONNECT request|CONNECT tunnel established, response 200}m;
my $curl_fail = sub {
    my $code = shift;
    qr{Received HTTP code $code from proxy after CONNECT|CONNECT tunnel failed, response $code}m;
};

subtest "basic", sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        plan skip_all => "curl does not support proxying over HTTP/3"
            if $curl =~ /--http3/;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error http://127.0.0.1:$origin_port/echo 2>&1`;
        like $content, $curl_success, "Connect got a 200 response to CONNECT";
        like $content, qr{proxy-status: h2o/test; next-hop=127\.0\.0\.1}i;
        my @c = $content =~ /$ok_resp/g;
        is @c, 2, "Got two 200 responses";
    });
};

subtest "acl" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        plan skip_all => "curl does not support proxying over HTTP/3"
            if $curl =~ /--http3/;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://8.8.8.8/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=destination_ip_prohibited}i;
        like $content, $curl_fail->(403);
    });
};

subtest "nxdomain" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        plan skip_all => "curl does not support proxying over HTTP/3"
            if $curl =~ /--http3/;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://doesnotexist.example.org/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=dns_error; rcode=NXDOMAIN}i;
        like $content, $curl_fail->(502);
    });
};

# This test assumes that nothing listens on port 1 (tcpmux).
subtest "refused" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        plan skip_all => "curl does not support proxying over HTTP/3"
            if $curl =~ /--http3/;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://127.0.0.1:1/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=connection_refused; next-hop=127\.0\.0\.1}i;
        like $content, $curl_fail->(502);
    });
};

subtest "broken request" => sub {
    plan skip_all => "nc not found"
        unless prog_exists("nc");
    my $resp = `echo "CONNECT abc HTTP/1.1\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
    like $resp, qr{^HTTP/1\.1 400 .*\nproxy-status: h2o/test; error=http_request_error; details="invalid host:port"}s;
};

done_testing;
