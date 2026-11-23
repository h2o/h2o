use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

# the upstream sends a 1xx response with END_STREAM set, followed by a final response
my $h2g = spawn_h2get_backend(<< 'EOC');
    if f.type == 'HEADERS' and (f.flags & END_STREAM) == END_STREAM then
        conn.send_headers({":status" => "100"}, f.stream_id, END_HEADERS | END_STREAM)
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_HEADERS | END_STREAM)
    end
EOC

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT

wait_port($h2g->{tls_port});

my $resp = `curl --silent --include -m 5 http://127.0.0.1:$server->{port}/ 2>&1`;
like $resp, qr{^HTTP/1\.1 502 }s, "status";
like $resp, qr{\r\n\r\nprotocol violation$}s, "error message";

$h2g->{kill}->();

done_testing;
