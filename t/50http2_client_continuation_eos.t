use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use File::Temp qw(tempfile tempdir);
use Net::EmptyPort qw(check_port wait_port);
use JSON;

my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });
my $code = shift;
my $h2g = spawn_h2get_backend(<< "EOC"
    if f.type == 'DATA' and f.flags & END_STREAM then
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_STREAM)
        conn.send_continuation({"cont" => "1"}, f.stream_id, END_HEADERS)
    end
EOC
);

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 20
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
        proxy.http2.force-cleartext: OFF
        proxy.http2.max-concurrent-streams: 1
        proxy.timeout.keepalive: 10000
EOT

wait_port($h2g->{tls_port});

run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        my $url = "$proto://127.0.0.1:$port";
        my $resp = `$curl_cmd -m 5 -X POST -d @/bin/ls -ksvo /dev/null $url $url 2>&1`;
        like $resp, qr{HTTP\/[0-9\.]+ 200.*?HTTP\/[0-9\.]+ 200}is, "$curl_cmd, two 200 ok";
        unlike $resp, qr{Operation timed out after}, "time out";
    });

my ($out, $err) = $h2g->{kill}->();
diag($out);
diag($err);

done_testing();
