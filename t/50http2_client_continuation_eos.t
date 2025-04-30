use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use File::Temp qw(tempfile tempdir);
use Net::EmptyPort qw(check_port wait_port);
use JSON;

sub dotest {
    my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });
    my $code = shift;
    my $h2g = spawn_h2get_backend($code);

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
        proxy.timeout.keepalive: 10000
EOT

    wait_port($h2g->{tls_port});

    my $resp;

    $resp = `curl -m 5 --http1.1 -X POST -d @/bin/ls -ksvo /dev/null https://127.0.0.1:$server->{tls_port} https://127.0.0.1:$server->{tls_port} 2>&1`;
    like $resp, qr{HTTP\/1.1 200.*?HTTP\/1.1 200}is, "h2, two 200 ok";
    unlike $resp, qr{Operation timed out after}, "time out";

    $resp = `curl -m 5 --http2 -X POST -d @/bin/ls -ksvo /dev/null https://127.0.0.1:$server->{tls_port} https://127.0.0.1:$server->{tls_port} 2>&1`;
    like $resp, qr{HTTP\/2 200.*?HTTP\/2 200}is, "h2, two 200 ok";
    unlike $resp, qr{Operation timed out after}, "time out";

    $resp = `curl -m 5 --http3 -X POST -d @/bin/ls -ksvo /dev/null https://127.0.0.1:$server->{quic_port} https://127.0.0.1:$server->{quic_port} 2>&1`;
    like $resp, qr{HTTP\/3 200.*?HTTP\/3 200}is, "h3, two 200 ok";
    unlike $resp, qr{Operation timed out after}, "time out";

    my ($out, $err) = $h2g->{kill}->();
}

dotest(<< "EOC"
    puts f.type
    puts f.stream_id
    if f.type == 'DATA' and f.flags & END_STREAM then
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_STREAM)
        conn.send_continuation({"cont" => "1"}, f.stream_id, END_HEADERS)
    end
EOC
);

done_testing();
