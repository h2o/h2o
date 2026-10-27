use strict;
use warnings;
use Test::More;
use t::Util;
use Net::EmptyPort qw(wait_port);

plan skip_all => "h2get not found"
    unless h2get_exists();

my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });
my $h2g = spawn_h2get_backend(<< "EOC"
    if f.type == 'HEADERS' and (f.flags & END_STREAM) == END_STREAM then
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_HEADERS)
        conn.send_headers({"trailer" => "1"}, f.stream_id, END_HEADERS | END_STREAM)
    end
EOC
);

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
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT

wait_port($h2g->{tls_port});

run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        my $url = "$proto://127.0.0.1:$port";
        my $resp = `$curl_cmd -m 5 -ksvo /dev/null $url 2>&1`;
        like $resp, qr{HTTP\/[0-9\.]+ 200}is, "$curl_cmd, 200 ok";
        # trailers of a response without body are tested only for HTTP/2
        like $resp, qr{trailer: 1}is, "$curl_cmd, found trailer"
            if $curl_cmd =~ /http2/;
        unlike $resp, qr{Operation timed out after}, "time out";
    });

my ($out, $err) = $h2g->{kill}->();
diag($out);
diag($err);

done_testing();
