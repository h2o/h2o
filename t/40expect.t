use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use Time::HiRes;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
send-informational: all
num-threads: 1
hosts:
  default:
    paths:
      /non-streaming:
        mruby.handler: |
          proc do |env|
            # \$stderr.puts env.inspect
            [200, {}, env['rack.input']]
          end
      /streaming:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/echo
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;

    for my $mode (qw(streaming non-streaming)) {
        my $resp = `$curl -s --dump-header /dev/stderr -X POST --data-binary -xxxxx -H "expect: 100-continue" '$proto://127.0.0.1:$port/$mode' 2>&1`;
        like $resp, qr{HTTP/[0-9.]+ 100\s.*HTTP/[0-9.]+ 200\s}is, $mode;
    }
});

done_testing;
