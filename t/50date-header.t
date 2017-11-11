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


my $no_date_server_port = empty_port();
$| = 1;
my $socket = new IO::Socket::INET (
    LocalHost => '127.0.0.1',
    LocalPort => $no_date_server_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
);
die "cannot create socket $!\n" unless $socket;

check_port($no_date_server_port) or die "can't connect to server socket";
# accent and close check_port's connection
my $client_socket = $socket->accept();
close($client_socket);

my $date_upstream_port = empty_port();
my $guard1 = spawn_server(
    argv     => [ "sh -c 'printf \"HTTP/1.0 200 Ok\r\ndate: Fri, 19 Feb 1473 00:00 +0000\r\nconnection:close\r\n\r\nOk\" | nc -w 1 -l $date_upstream_port > /dev/null 2>&1'" ],
    is_ready =>  sub {
        sleep(1);
        return 1;
    },
);

my $no_date_upstream_port = empty_port();
my $guard2 = spawn_server(
    argv     => [ "sh -c 'printf \"HTTP/1.0 200 Ok\r\nconnection:close\r\n\r\nOk\" | nc -w 1 -l $no_date_upstream_port > /dev/null 2>&1'" ],
    is_ready =>  sub {
        sleep(1);
        return 1;
    },
);

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

my $curl = 'curl --silent --dump-header /dev/stderr';
subtest 'proxy' => sub {
    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/proxy-no-date 2>&1");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    unlike $headers, qr/^date:/mi, 'date request header is not set';

    ($headers, $body) = run_prog("$curl -Hdate:now http://127.0.0.1:@{[$server->{port}]}/proxy-date");
    like $headers, qr/^HTTP\/1\.1 200 Ok/mi, 'succesful request';
    like $headers, qr/^date:/mi, 'date request header found when set by upstream';

};

subtest 'mruby' => sub {
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
