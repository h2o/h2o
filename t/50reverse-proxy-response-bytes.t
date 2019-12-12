use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use Time::HiRes qw(sleep);
use IO::Socket::INET;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $logfile = "$tempdir/access.log";
my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 10
hosts:
  default:
    paths:
      "/":
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
access-log:
  path: $logfile
  format: "@{[ join("\\t", map { "proxy.response-bytes$_:%{proxy.response-bytes$_}x" } ('', '-header', '-body')) ]}"
EOT

subtest 'non-streaming' => sub {
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/alice.txt");
    like $headers, qr{^HTTP/1\.1 200 }s;

    sleep 0.1;

    my $expected_body_size = 1661;

    # expects 217 bytes headers like below
    # HTTP/1.1 200 OK\r\n
    # Date: Thu, 12 Dec 2019 00:12:34 GMT\r\n
    # Server: Plack::Handler::Starlet\r\n
    # Content-Type: text/plain; charset=utf-8\r\n
    # Content-Length: 1661\r\n
    # Last-Modified: Mon, 04 Sep 2017 02:34:00 GMT\r\n
    # Connection: close\r\n
    # \r\n

    my $expected_header_size = 217;

    my $log = parse_log();
    is $log->{'proxy.response-bytes-body'}, $expected_body_size, 'body';
    is $log->{'proxy.response-bytes-header'}, $expected_header_size, 'header';
    is $log->{'proxy.response-bytes'}, $expected_body_size + $expected_header_size, 'total';
};

subtest 'streaming' => sub {
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/streaming-body?count=10");
    like $headers, qr{^HTTP/1\.1 200 }s;

    sleep 0.1;

    # expects 66 bytes (11 bytes content + 55 bytes chunked overhead)
    my $expected_body_size = 66;

    # expects 162 bytes headers like below
    # HTTP/1.1 200 OK\r\n
    # Date: Thu, 12 Dec 2019 00:09:06 GMT\r\n
    # Server: Plack::Handler::Starlet\r\n
    # content-type: text/plain\r\n
    # Transfer-Encoding: chunked\r\n
    # Connection: close\r\n
    # \r\n
    my $expected_header_size = 162;

    my $log = parse_log();
    is $log->{'proxy.response-bytes-body'}, $expected_body_size, 'body';
    is $log->{'proxy.response-bytes-header'}, $expected_header_size, 'header';
    is $log->{'proxy.response-bytes'}, $expected_body_size + $expected_header_size, 'total';
};

subtest 'receive header and body at once' => sub {
    # Starlet send headers and body at once if the body object is ARRAY and content is small
    my $query = 'resp:content-length=22';
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr 'http://127.0.0.1:$server->{port}/echo-query?$query'");
    like $headers, qr{^HTTP/1\.1 200 }s;
    is $body, $query;

    sleep 0.1;

    my $expected_body_size = 22;

    # expects 154 bytes headers like below
    # HTTP/1.1 200 OK\r\n
    # Date: Thu, 12 Dec 2019 00:02:55 GMT\r\n
    # Server: Plack::Handler::Starlet\r\n
    # content-type: text/plain\r\n
    # content-length: 22\r\n
    # Connection: close\r\n
    # \r\n
    my $expected_header_size = 154;

    my $log = parse_log();
    is $log->{'proxy.response-bytes-body'}, $expected_body_size, 'body';
    is $log->{'proxy.response-bytes-header'}, $expected_header_size, 'header';
    is $log->{'proxy.response-bytes'}, $expected_body_size + $expected_header_size, 'total';
};

sub parse_log {
    my @log = do {
        open my $fh, "<", $logfile
            or die "failed to open $logfile: $!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };
    my $log = pop(@log);
    my %map = map { split(':', $_) } split("\t", $log);
    return \%map;
}

subtest 'include bytes of 1xx' => sub {
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr 'http://127.0.0.1:$server->{port}/early-hints'");
    like $headers, qr{^HTTP/1\.1 200 }s;

    sleep 0.1;

    my $expected_body_size = 11;

    # expects 144 bytes headers like below
    # HTTP/1.1 103 Early Hints\r\n
    # link: </index.js>; rel=preload\r\n
    # \r\n
    # HTTP/1.1 200 OK\r\n
    # connection: close\r\n
    # content-type: text/plain\r\n
    # content-length: 11\r\n
    # \r\n
    my $expected_header_size = 144;

    my $log = parse_log();
    is $log->{'proxy.response-bytes-body'}, $expected_body_size, 'body';
    is $log->{'proxy.response-bytes-header'}, $expected_header_size, 'header';
    is $log->{'proxy.response-bytes'}, $expected_body_size + $expected_header_size, 'total';
};

done_testing();

