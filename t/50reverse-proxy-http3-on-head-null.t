use strict;
use warnings;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

# Tests that the HTTP/3 client handles `on_head` returning NULL for a HEADERS frame that is not the end of the stream. Internal
# redirect is used as the means to have the proxy return NULL from `on_head`.

my $upstream_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $upstream = spawn_h2o_raw(<< "EOT", [{host => "127.0.0.1", port => $upstream_port, proto => "udp"}]);
listen:
  type: quic
  host: 127.0.0.1
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /redirect:
        # delay the end of the body so that the HEADERS frame is processed before the stream is closed
        mruby.handler: |
          class SlowBody
            def each
              yield "moved"
              sleep 1
            end
          end
          Proc.new do |env|
            [302, {"location" => "/index.txt"}, SlowBody.new]
          end
      /:
        file.dir: t/assets/doc_root
EOT

# the delegated request lets the proxy handle the redirect internally, returning NULL from on_head
my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /proxied:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.http3.ratio: 100
      /:
        reproxy: ON
        mruby.handler: proc {|env| [200, {"x-reproxy-url" => "/proxied/redirect"}, []] }
EOT

my $resp = `curl --silent --dump-header /dev/stdout http://127.0.0.1:$server->{port}/`;
like $resp, qr{^HTTP/[^ ]* 200.*^hello$}msi, "internal redirect";
$resp = `curl --silent --dump-header /dev/stdout http://127.0.0.1:$server->{port}/proxied/index.txt`;
like $resp, qr{^HTTP/[^ ]* 200}mi, "server is still alive";

done_testing;
