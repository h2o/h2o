use strict;
use warnings;
use Test::More;
use Net::EmptyPort qw(check_port empty_port);
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
proxy-status.identity: "h2o/test"
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+127.0.0.1:$origin_port"
          - "+127.0.0.1:1"
        proxy.connect.proxy-status: ON
EOT

my $ok_resp = qr{HTTP/[^ ]+ 200\s}m;

subtest "basic", sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error http://127.0.0.1:$origin_port/echo 2>&1`;
        like $content, qr{Proxy replied 200 to CONNECT request}m, "Connect got a 200 response to CONNECT";
        my @c = $content =~ /$ok_resp/g;
        is @c, 2, "Got two 200 responses";
    });
};

subtest "acl" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://8.8.8.8/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=destination_ip_prohibited}i;
        like $content, qr{Received HTTP code 403 from proxy after CONNECT};
    });
};

subtest "nxdomain" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://doesnotexist.example.org/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=dns_error; rcode=NXDOMAIN}i;
        like $content, qr{Received HTTP code 502 from proxy after CONNECT};
    });
};

# This test assumes that nothing listens on port 1 (tcpmux).
subtest "refused" => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $content = `$curl --proxy-insecure -p -x $proto://127.0.0.1:$port --silent -v --show-error https://127.0.0.1:1/ 2>&1`;
        like $content, qr{proxy-status: h2o/test; error=connection_refused}i;
        like $content, qr{Received HTTP code 502 from proxy after CONNECT};
    });
};

done_testing;
