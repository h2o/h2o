use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port wait_port);
use File::Temp qw(tempdir);
use JSON;
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $conf = << "EOT";
access-log:
    format: '{"protocol":"%H","cc.name":"%{cc.name}x","delivery_rate":"%{delivery-rate}x"}'
    escape: json
    path: "$tempdir/access_log"
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  cc: pico
num-threads: 1
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
my $server = spawn_h2o($conf);

sub truncate_access_log {
    open my $fh, ">", "$tempdir/access_log" or die $!;
}

subtest "HTTP/1.1", sub {
    truncate_access_log();

    for (1 .. 3) {
        my $resp = `$client_prog http://127.0.0.1:$server->{port} 2>&1`;
        like $resp, qr{^HTTP/1\.1 .*\n\nhello\n}ms, "http/1 is ok";
    }

    my @logs = map { decode_json($_) } do {
        open my $fh, "<", "$tempdir/access_log" or die $!;
        <$fh>;
    };
    diag(explain(\@logs)) if $ENV{TEST_DEBUG};

    is $logs[0]{"protocol"}, "HTTP/1.1", "protocol";
    ok $logs[0]{"cc.name"}, "cc.name";
    ok exists($logs[0]{"delivery_rate"}), "delivery_rate";
    # cmp_ok $logs[0]{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

subtest "HTTP/2", sub {
    truncate_access_log();

    for (1 .. 3) {
        my $resp = `$client_prog -2 100 -k https://127.0.0.1:$server->{tls_port} 2>&1`;
        like $resp, qr{^HTTP/2 .*\n\nhello\n}ms, "http/2 is ok";
    }

    my @logs = map { decode_json($_) } do {
        open my $fh, "<", "$tempdir/access_log" or die $!;
        <$fh>;
    };
    diag(explain(\@logs)) if $ENV{TEST_DEBUG};

    is $logs[0]{"protocol"}, "HTTP/2", "protocol";
    ok $logs[0]{"cc.name"}, "cc.name";
    ok exists($logs[0]{"delivery_rate"}), "delivery_rate";
    # cmp_ok $logs[0]{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

subtest "HTTP/3", sub {
    truncate_access_log();

    for (1 .. 3) {
        my $resp = `$client_prog -3 100 -k https://127.0.0.1:$quic_port 2>&1`;
        like $resp, qr{^HTTP/3 .*\n\nhello\n}ms, "http/3 is ok";
    }

    my @logs = map { decode_json($_) } do {
        open my $fh, "<", "$tempdir/access_log" or die $!;
        <$fh>;
    };
    diag(explain(\@logs)) if $ENV{TEST_DEBUG};

    is $logs[0]{"protocol"}, "HTTP/3", "protocol";
    ok $logs[0]{"cc.name"}, "cc.name";
    ok exists($logs[0]{"delivery_rate"}), "delivery_rate";
    # cmp_ok $logs[0]{"delivery_rate"}, ">", 0, "delivery_rate is greater than zero";
};

done_testing;
