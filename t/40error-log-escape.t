use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use File::Temp qw(tempfile);

my ($ignored, $fn) = tempfile(UNLINK => 1);

plan skip_all => 'curl not found'
    unless prog_exists('curl') and curl_supports_http2();

my $upstream_port = empty_port();
my $server = spawn_h2o(<< "EOT");
error-log: $fn
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.timeout.io: 2000
        proxy.timeout.keepalive: 0
EOT

my $tls_port = $server->{tls_port};

my $res = `curl -sk --http2 --max-time 5 --dump-header /dev/stderr 'https://127.0.0.1:$tls_port/%s' 2>&1 > /dev/null`;
like $res, qr{^HTTP/2(\.0)? 502 }, "502 response on upstream error";

$res = `curl -sk --http2 --max-time 5 --dump-header /dev/stderr 'https://127.0.0.1:$tls_port/%s012345678901234567890123456789' 2>&1 > /dev/null`;
like $res, qr{^HTTP/2(\.0)? 502 }, "502 response on upstream error";

open(FH, "<" . $fn) or die "cannot open error log";
my $i = 0;
while(<FH>) {
    if (/lib\/core\/proxy\.c/) {
        if ($i == 0) {
            like $_, qr{\[lib/core/proxy\.c\] in request:/%s:connection failure}, "Error logged has % properly escaped";
        } else {
            like $_, qr{\[lib/core/proxy\.c\] in request:/%s01234567890123456789012345\.\.\.:connection failure}, "Error logged has % properly escaped, and is truncated";
        }
        $i++;
    }
}

done_testing();
