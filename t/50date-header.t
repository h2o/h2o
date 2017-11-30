use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
plan skip_all => 'cannot run perl -MPlack::Handler::FCGI'
    if system("perl -MPlack::Handler::FCGI /dev/null > /dev/null 2>&1") != 0;


my $date_upstream_port = empty_port();
my $no_date_upstream_port = empty_port();

my $fcgi_port = empty_port();
my $fcgi_upstream = spawn_server(
    argv => [ qw(plackup -s FCGI --access-log /dev/stderr --listen), "127.0.0.1:$fcgi_port", ASSETS_DIR . "/upstream.psgi", ],
    is_ready => sub {
        check_port($fcgi_port);
    },
);

my $server = spawn_h2o(<< "EOT");
proxy.timeout.keepalive: 0
hosts:
  default:
    paths:
      /proxy-date:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$date_upstream_port
      /proxy-no-date:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$no_date_upstream_port
      /mruby-date:
        mruby.handler: |
          Proc.new do |env|
            [200, [["content-type", "text/plain"], ["date", "Fri, 19 Feb 1473 00:00 +0000"]], []]
          end
      /mruby-no-date:
        mruby.handler: |
          Proc.new do |env|
            [200, [["content-type", "text/plain"]], []]
          end
      /file:
        file.dir: @{[DOC_ROOT]}
EOT

my $server_no_missing_date = spawn_h2o(<< "EOT");
proxy.emit-missing-date-header: OFF
proxy.timeout.keepalive: 0
hosts:
  default:
    paths:
      /proxy-date:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$date_upstream_port
      /proxy-no-date:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$no_date_upstream_port
      /mruby-date:
        mruby.handler: |
          Proc.new do |env|
            [200, [["content-type", "text/plain"], ["date", "Fri, 19 Feb 1473 00:00 +0000"]], []]
          end
      /mruby-no-date:
        mruby.handler: |
          Proc.new do |env|
            [200, [["content-type", "text/plain"]], []]
          end
      /file:
        file.dir: @{[DOC_ROOT]}
EOT

my $curl = 'curl --silent --dump-header /dev/stderr';
subtest 'proxy emit missing date' => sub {
    my $guard1 = one_shot_http_upstream("HTTP/1.0 200 Ok\r\ndate: Fri, 19 Feb 1473 00:00 +0000\r\nconnection:close\r\n\r\nOk", $date_upstream_port);
    my $guard2  = one_shot_http_upstream("HTTP/1.0 200 Ok\r\nconnection:close\r\n\r\nOk", $no_date_upstream_port);

    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/proxy-no-date 2>&1");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header is set';

    ($headers, $body) = run_prog("$curl -Hdate:now http://127.0.0.1:@{[$server->{port}]}/proxy-date");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header found when set by upstream';

};

subtest 'proxy no emit missing date' => sub {
    my $guard1 = one_shot_http_upstream("HTTP/1.0 200 Ok\r\ndate: Fri, 19 Feb 1473 00:00 +0000\r\nconnection:close\r\n\r\nOk", $date_upstream_port);
    my $guard2  = one_shot_http_upstream("HTTP/1.0 200 Ok\r\nconnection:close\r\n\r\nOk", $no_date_upstream_port);

    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server_no_missing_date->{port}]}/proxy-no-date 2>&1");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    unlike $headers, qr/^date:/mi, 'date request header is not set';

    ($headers, $body) = run_prog("$curl -Hdate:now http://127.0.0.1:@{[$server_no_missing_date->{port}]}/proxy-date");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header found when set by upstream';

};

subtest 'mruby' => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};
    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/mruby-date");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date: Fri, 19 Feb 1473 00:00 \+0000/mi, 'date request header is set by mruby';

    ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/mruby-no-date");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header is set';
};

subtest 'file' => sub {
    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/file/");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header is set';
};




done_testing();
