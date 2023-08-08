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

subtest "basic", sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error http://127.0.0.1:$origin_port/echo 2>&1`;
        like $content, qr{Proxy replied 200 to CONNECT request|CONNECT tunnel established, response 200}m, "Connect got a 200 response to CONNECT";
        like $content, qr{proxy-status: h2o/test; next-hop=127\.0\.0\.1}i;
        my @c = $content =~ /$ok_resp/g;
        is @c, 2, "Got two 200 responses";
    });
};

subtest "acl" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://8.8.8.8/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=destination_ip_prohibited}i;
        like $content, qr{Received HTTP code 403 from proxy after CONNECT|CONNECT tunnel failed, response 403};
    });
};

subtest "nxdomain" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://doesnotexist.example.org/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=dns_error; rcode=NXDOMAIN}i;
        # Error messages vary in curl versions
        like $content, qr{Received HTTP code 502 from proxy after CONNECT|CONNECT tunnel failed, response 502};
    });
};

# This test assumes that nothing listens on port 1 (tcpmux).
subtest "refused" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://127.0.0.1:1/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=connection_refused; next-hop=127\.0\.0\.1}i;
        like $content, qr{Received HTTP code 502 from proxy after CONNECT|CONNECT tunnel failed, response 502};
    });
};

done_testing;
