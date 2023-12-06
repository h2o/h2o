use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
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

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $conf = << "EOT";
access-log:
    format: '{"protocol":"%H","delivery_rate":"%{delivery-rate}x"}'
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
      /:
        mruby.handler: |
          Proc.new do |env|
            payload = "." * (5 * 1024 * 1024)
            [200, {}, [payload]]
          end
EOT
my $server = spawn_h2o($conf);

sub truncate_access_log {
    open my $fh, ">", "$tempdir/access_log" or die $!;
}

sub load_logs {
    open my $fh, "<", "$tempdir/access_log" or die $!;
    my @json_logs = <$fh>;
    debug(@json_logs);
    return map { decode_json($_) } @json_logs;
}

subtest "HTTP/1.1", sub {
    truncate_access_log();

    my $resp = `$client_prog http://127.0.0.1:$server->{port} 2>&1`;
    like $resp, qr{^HTTP/1\.1 200\b}ms, "http/1 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/1.1", "protocol";
    cmp_ok $log->{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

subtest "HTTP/2", sub {
    truncate_access_log();

    my $resp = `$client_prog -2 100 -k https://127.0.0.1:$server->{tls_port} 2>&1`;
    like $resp, qr{^HTTP/2 200\b}ms, "http/2 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/2", "protocol";
    cmp_ok $log->{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

subtest "HTTP/3", sub {
    truncate_access_log();

    my $resp = `$client_prog -3 100 -k https://127.0.0.1:$quic_port 2>&1`;
    like $resp, qr{^HTTP/3 200\b}ms, "http/3 is ok";

    sleep 0.1;

    my ($log) = load_logs();

    is $log->{"protocol"}, "HTTP/3", "protocol";
    cmp_ok $log->{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

done_testing;
