use strict;
use warnings;
use Test::More;
use t::Util;
use File::Temp qw(tempfile);
use JSON;

plan skip_all => "h2get not found"
    unless h2get_exists();

# An origin that sends a header block larger than H2O_MAX_REQLEN makes the HTTP/2 client of the
# proxy refuse the response; the frames that carry a header block are not subject to flow control,
# so the client would otherwise allocate an arbitrary amount of memory (VULN-004).

my $h2g = spawn_h2get_backend(<< "EOC"
    if f.type == 'HEADERS' and (f.flags & END_STREAM) != END_STREAM then
        # open a header block without END_HEADERS, and then send continuation frames that carry
        # a header block that is larger than the limit that the client is allowed to accept
        conn.send_headers({":status" => "200"}, f.stream_id, 0)
        for i in 1..300 do
            conn.send_continuation({"h" + i.to_s => ("X" * 4096)}, f.stream_id, 0)
        end
    end
    if f.type == "DATA" and f.len > 0
        conn.send_window_update(0, f.len)
        conn.send_window_update(f.stream_id, f.len)
    end
EOC
);

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 20
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl_cmd) = @_;
    my $url = "$proto://127.0.0.1:$port";
    my $resp = `$curl_cmd -m 10 -svo /dev/null $url 2>&1`;
    # the proxy refuses the response of the origin: the request fails instead of the client
    # allocating an unbounded buffer
    unlike $resp, qr{HTTP/[\d.]+ 200}, "the response of the origin that sends an oversized header block is not forwarded";
    like $resp, qr{HTTP/[\d.]+ 50[0-9]}, "the proxy responds with a server error" or diag $resp;
});

my ($out, $err) = $h2g->{kill}->();
diag($out);
diag($err);

done_testing();