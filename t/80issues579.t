use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

# spawn upstream
my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $upstream_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

# spawn server
my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [399, {"link" => "</assets/index.js>; rel=preload"}, []]
          end
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /assets:
        file.dir: @{[DOC_ROOT]}
EOT

my $resp = `nghttp -n --stat "http://127.0.0.1:$server->{port}/index.txt"`;
like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.js\n.*\s/index\.txt\n}is, 'should receive pushed blocking asset from file handler before the main response';

done_testing;
