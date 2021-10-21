use strict;
use warnings;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $keep_alive_upstream_port = empty_port();
my $close_conn_upstream_port = empty_port();
my $curl = 'curl --silent --dump-header /dev/stderr';

subtest 'basic' => sub {
    my $doit = sub {
        my ($toggle) = @_;
        my $server = spawn_h2o(<< "EOT");
proxy.forward.close-connection: $toggle
hosts:
  default:
    paths:
      "/ka-origin":
        - proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
      "/cc-origin":
        - proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
EOT
        my $g1 = one_shot_http_upstream("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nOk", $keep_alive_upstream_port);
        my $g2 = one_shot_http_upstream("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOk", $close_conn_upstream_port);

        my ($headers, undef) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/ka-origin 2>&1");
        like $headers, qr/^Connection: keep-alive/mi, 'connection header has value: keep-alive';

        ($headers, undef) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/cc-origin 2>&1");
        my $expected = $toggle eq 'ON' ? 'close' : 'keep-alive';
        like $headers, qr/^Connection: $expected/mi, 'header forwarding successful';
    };

    subtest 'enabled' => sub {
        $doit->("ON");
    };
    subtest 'disabled' => sub {
        $doit->("OFF");
    };
};

done_testing();
