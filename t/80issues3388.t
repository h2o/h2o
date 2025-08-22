use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => "curl not found"
    unless prog_exists("curl");
plan skip_all => "curl does not support HTTP/3"
    unless curl_supports_http3();
plan skip_all => "h2get not found"
    unless h2get_exists();

my $tempdir = tempdir(CLEANUP => 1);

my $backend = spawn_h2get_backend(<< 'EOT');
if f.type == 'HEADERS'
  resp = {
    ":status" => "401",
    "hello" => "world",
  }
  conn.send_headers(resp, f.stream_id, END_HEADERS | END_STREAM)
  # sleep 5
  conn.send_rst_stream(f.stream_id, 5)
end
EOT

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$backend->{tls_port}/
        proxy.http2.ratio: 100
        proxy.ssl.verify-peer: OFF
access-log: /dev/stdout
EOT

subtest "tiny-req" => sub {
    doit(10);
} if 1;

subtest "huge-req" => sub {
    doit(2_000_000);
};

undef $server;
undef $backend;

done_testing;

sub doit {
    my $reqsize = shift;

    open my $fh, '>', "$tempdir/req"
        or die "failed to open file $tempdir/req:$!";
    print $fh 'A' x $reqsize;
    close $fh;

    my $resp = `curl --silent --insecure --http3 --include --data \@$tempdir/req https://127.0.0.1:$server->{quic_port} 2>&1`;
   like $resp, qr{^HTTP/3 401.*\nhello: world}s;
}
