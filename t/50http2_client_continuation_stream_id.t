use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

# the upstream sends a HEADERS frame without END_HEADERS, followed by a CONTINUATION frame on a different stream
my $h2g = spawn_h2get_backend(<< "EOC");
    if f.type == 'HEADERS' then
        conn.send_headers({":status" => "200"}, f.stream_id, 0)
        conn.send_continuation({"content-length" => "0"}, f.stream_id + 2, END_HEADERS)
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

my $resp = `curl --silent --show-error --max-time 5 --dump-header /dev/stdout http://127.0.0.1:$server->{port}/ 2>&1`;
like $resp, qr{^HTTP/[0-9.]+ 502}s, "502 is returned";

$h2g->{kill}->();

done_testing();
