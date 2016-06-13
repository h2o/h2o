use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

# start upstream
my $upstream = empty_port();
my $upstream_guard = spawn_server(
    argv     => [
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), "127.0.0.1:$upstream",
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready =>  sub {
        check_port($upstream);
    },
);

my $error_upstream = empty_port();
my $error_upstream_guard = spawn_server(
    argv     => [
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), "127.0.0.1:$error_upstream",
        "-e", 'sub { [200, [], [123]] }',
    ],
    is_ready =>  sub {
        check_port($error_upstream);
    },
);

subtest "internal-redirect-from-proxy" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream/
        error-doc:
          status: 404
          url: http://127.0.0.1:$error_upstream/
EOT
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello\n";

    ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/notfound");
    like $headers, qr{^HTTP/1\.1 404 }is;
    is $body, "123";
};

subtest "internal-redirect-within-proxy" => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};
    my $server = spawn_h2o(<< "EOT");
reproxy: ON
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          Proc.new do |env|
            [200, { "x-reproxy-url" => "/proxy/?resp:status=302&resp:location=/index.txt" }, ["from mruby"]]
          end
      "/proxy":
        proxy.reverse.url: http://127.0.0.1:$upstream/
EOT
    my ($headers, $body) = run_prog("curl --max-redirs 0 --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello\n";
};

done_testing;
