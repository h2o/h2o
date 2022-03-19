# Set TEST_DEBUG=1 to dump access logs

use strict;
use warnings;
use Net::EmptyPort qw(empty_port wait_port check_port);
use File::Temp qw(tempdir);
use JSON;
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;
plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

my $tempdir = tempdir(CLEANUP => 1);

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $conf = << "EOT";
access-log:
    format: '{
                "protocol":"%H"
                , "connection-id":%{connection-id}x
                , "connect-time":%{connect-time}x
                , "request-total-time":%{request-total-time}x
                , "request-header-time":%{request-header-time}x
                , "request-body-time":%{request-body-time}x
                , "process-time":%{process-time}x
                , "response-time":%{response-time}x
                , "duration":%{duration}x
                , "total-time":%{total-time}x
                , "error":"%{error}x"
                , "proxy.idle-time":%{proxy.idle-time}x
                , "proxy.connect-time":%{proxy.connect-time}x
                , "proxy.request-time":%{proxy.request-time}x
                , "proxy.process-time":%{proxy.process-time}x
                , "proxy.response-time":%{proxy.response-time}x
                , "proxy.total-time":%{proxy.total-time}x
            }'
    escape: json
    path: "$tempdir/access_log"
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
num-threads: 1
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
my $server = spawn_h2o($conf);

sub truncate_access_log {
    open my $fh, ">", "$tempdir/access_log" or die $!;
}

sub load_logs {
    open my $fh, "<", "$tempdir/access_log" or die $!;
    my @json_logs = <$fh>;
    diag(@json_logs) if $ENV{TEST_DEBUG};
    return map { decode_json($_) } @json_logs;
}

# it takes at least 0.100 sec in total
my $path = "streaming-body?sleep=0.01&count=10";

subtest "HTTP/1.1", sub {
    truncate_access_log();

    my $resp = `$client_prog 'http://127.0.0.1:$server->{port}/$path' 2>&1`;
    like $resp, qr{^HTTP/1\.1 200\b}ms, "http/1 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/1.1", "protocol";

    like $log->{"connection-id"}, qr/^\d+$/;
    cmp_ok $log->{"connect-time"}, ">", 0;
    cmp_ok $log->{"request-total-time"}, ">=", 0;
    cmp_ok $log->{"request-header-time"}, ">=", 0;
    cmp_ok $log->{"request-body-time"}, ">=", 0;
    cmp_ok $log->{"process-time"}, ">=", 0;
    cmp_ok $log->{"response-time"}, ">=", 0.100;
    cmp_ok $log->{"total-time"}, ">=", 0.100;
    is $log->{"error"}, "";
    cmp_ok $log->{"duration"}, ">=", 0.100;
    cmp_ok $log->{"proxy.idle-time"}, ">=", 0;
    cmp_ok $log->{"proxy.connect-time"}, ">", 0;
    cmp_ok $log->{"proxy.request-time"}, ">=", 0;
    cmp_ok $log->{"proxy.process-time"}, ">", 0;
    cmp_ok $log->{"proxy.response-time"}, ">", 0.100;
    cmp_ok $log->{"proxy.total-time"}, ">", 0.100;
};

subtest "HTTP/2", sub {
    truncate_access_log();

    my $resp = `$client_prog -2 100 -k 'https://127.0.0.1:$server->{tls_port}/$path' 2>&1`;
    diag($resp);
    like $resp, qr{^HTTP/2 200\b}ms, "http/2 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/2", "protocol";

    like $log->{"connection-id"}, qr/^\d+$/;
    cmp_ok $log->{"connect-time"}, ">", 0;
    cmp_ok $log->{"request-total-time"}, ">=", 0;
    cmp_ok $log->{"request-header-time"}, ">=", 0;
    cmp_ok $log->{"request-body-time"}, ">=", 0;
    cmp_ok $log->{"process-time"}, ">=", 0;
    cmp_ok $log->{"response-time"}, ">=", 0.100;
    cmp_ok $log->{"total-time"}, ">=", 0.100;
    is $log->{"error"}, "";
    cmp_ok $log->{"duration"}, ">=", 0.100;
    cmp_ok $log->{"proxy.idle-time"}, ">=", 0;
    cmp_ok $log->{"proxy.connect-time"}, ">", 0;
    cmp_ok $log->{"proxy.request-time"}, ">=", 0;
    cmp_ok $log->{"proxy.process-time"}, ">", 0;
    cmp_ok $log->{"proxy.response-time"}, ">", 0.100;
    cmp_ok $log->{"proxy.total-time"}, ">", 0.100;
};

subtest "HTTP/3", sub {
    truncate_access_log();

    my $resp = `$client_prog -3 100 -k 'https://127.0.0.1:$quic_port/$path' 2>&1`;
    like $resp, qr{^HTTP/3 200\b}ms, "http/3 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/3", "protocol";

    like $log->{"connection-id"}, qr/^\d+$/;
    cmp_ok $log->{"connect-time"}, ">", 0;
    cmp_ok $log->{"request-total-time"}, ">=", 0;
    cmp_ok $log->{"request-header-time"}, ">=", 0;
    cmp_ok $log->{"request-body-time"}, ">=", 0;
    cmp_ok $log->{"process-time"}, ">=", 0;
    cmp_ok $log->{"response-time"}, ">=", 0.100;
    cmp_ok $log->{"total-time"}, ">=", 0.100;
    is $log->{"error"}, "";
    cmp_ok $log->{"duration"}, ">=", 0.100;
    cmp_ok $log->{"proxy.idle-time"}, ">=", 0;
    cmp_ok $log->{"proxy.connect-time"}, ">", 0;
    cmp_ok $log->{"proxy.request-time"}, ">=", 0;
    cmp_ok $log->{"proxy.process-time"}, ">", 0;
    cmp_ok $log->{"proxy.response-time"}, ">", 0.100;
    cmp_ok $log->{"proxy.total-time"}, ">", 0.100;
};

done_testing;
