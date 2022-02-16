use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

my $upstream_port = empty_port({ host => '0.0.0.0' });
my $upstream = spawn_server(
    argv => [
        qw(
            plackup -s Standalone --ssl=1 --ssl-key-file=examples/h2o/server.key --ssl-cert-file=examples/h2o/server.crt --port
        ),
        $upstream_port, ASSETS_DIR . "/upstream.psgi"
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

subtest "reverse-proxy" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/verify-fail":
        proxy.reverse.url: https://127.0.0.1:$upstream_port
      "/no-verify":
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.ssl.verify-peer: OFF
      "/verify-success":
        proxy.reverse.url: https://localhost.examp1e.net:$upstream_port/echo
        proxy.ssl.cafile: misc/test-ca/root/ca.crt
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/verify-fail/ 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]* 502\s}is;
        $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/no-verify/ 2>&1 > /dev/null`;
        unlike $resp, qr{^HTTP/[^ ]* 502\s}is;
        $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://localhost.examp1e.net:$port/verify-success 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]* 200\s}is;
    });
};

subtest "reproxy" => sub {
    plan skip_all => "mruby support is off"
        unless server_features()->{mruby};
    my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      "/":
        reproxy: ON
        mruby.handler: |
          Proc.new do |env|
            [200, {"x-reproxy-url" => "https://127.0.0.1:$upstream_port/index.txt"}, ["should never see this"]]
          end
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout --max-redirs 0 $proto://127.0.0.1:$port/`;
        like $resp, qr{^HTTP/[^ ]* 200}im;
        like $resp, qr{^hello$}m;
    });
};

subtest "preserve.host" => sub {
    my $doit = sub {
        my $flag = shift;
        my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
proxy.preserve-host: @{[ $flag ? "ON" : "OFF" ]}
proxy.ssl.session-cache: OFF # SSL_get_servername returns NULL if a session (that didn't ack the use of SNI in SH) is resumed (https://github.com/openssl/openssl/commit/a75be9f)
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: https://127.0.0.1:$upstream_port
EOT

        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://2130706433:$port/sni-name`;
            is $resp, "127.0.0.1";
        });
    };
    subtest "off" => sub {
        $doit->(0);
    };
    subtest "on" => sub {
        $doit->(1);
    };
};

done_testing();
