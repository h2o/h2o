use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port wait_port);
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;
plan skip_all => "nc not found"
    unless prog_exists("nc");

my $up_port = empty_port();
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});


my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$up_port
EOT

# setup upstream server, populating it with response, but still open
my $up_pid = open my $up_resp, '|-', "exec nc -l 127.0.0.1 $up_port > $tempdir/up_req.txt"
    or die "failed to launch nc:$!";
$up_resp->autoflush(1);
print $up_resp "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello";

sleep 1;

# open client, sending request body at 12KB/sec. The number is slightly greater than H2O_HTTP3_REQUEST_BODY_MIN_BYTES_TO_BLOCK, and
# the expectation is that h2o would start streaming the request body
open my $client_resp, '-|', "$client_prog -3 100 -b 120000 -c 12000 -i 1000 -m POST https://127.0.0.1:$quic_port 2>&1"
    or die "failed to launch $client_prog:$!";

# wait until the request received by upstream is 3 seconds' worth of data
for (my $cnt = 0;; ++$cnt) {
    if ($cnt > 40) {
        fail "taking too long";
        done_testing;
        exit;
    }
    if (-e "$tempdir/up_req.txt") {
        my $up_req_size = (stat "$tempdir/up_req.txt")[7];
        last if $up_req_size > 12000 * 3;
    }
    sleep 0.25;
}

# kill nc
kill 'KILL', $up_pid;
undef $up_resp;

subtest "request-received-upstream" => sub {
    my $up_req = do {
        open my $fh, "<", "$tempdir/up_req.txt"
            or die "failed to open $tempdir/up_req.txt:$!";
        local $/;
        <$fh>;
    };
    my ($headers, $body) = split /\r\n\r\n/, $up_req, 2;
    like $headers, qr{^POST / HTTP/1\.1\r\n}s;
    like $headers, qr{^content-length: 120000($|\r\n)}m;
    like $body, qr{^a+$}s;
    cmp_ok length($body), '>=', 12000 * 3;
    cmp_ok length($body), '<', 12000 * 7;
};

subtest "response" => sub {
    my $resp = do {
        local $/;
        <$client_resp>;
    };
    my ($headers, $body) = split /\n\n/, $resp, 2;
    like $headers, qr{^HTTP/3 200\n}s;
    is $body, "hello";
};

done_testing;
