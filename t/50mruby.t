use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub fetch {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return (`curl --silent /dev/stderr -H User-Agent:h2o_mruby_test http://127.0.0.1:$server->{port}/ 2>&1`, $server->{port});
}

sub fetch_header {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1`;
}

sub fetch_uri {
    my ($extra_conf, $uri) = @_;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return `curl --silent /dev/stderr http://127.0.0.1:$server->{port}/$uri 2>&1`;
}

my ($resp, $port) = fetch(<< 'EOT');
        mruby.handler-file: t/50mruby/hello.rb
EOT
is $resp, "hello from h2o_mruby\n", "resoponse body from mruby (separate)";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          h = "hello"
          m =  "from h2o_mruby"
          h + " " + m + "\n"
EOT
is $resp,"hello from h2o_mruby\n", "response body from mruby (inline)";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O.max_headers.to_s
EOT
is $resp, "100", "H2O.max_headers method";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          r = H2O::Request.new
          ua = r.headers_in["User-Agent"]
          r.headers_in["User-Agent"] = "new-#{ua}"
          r.headers_in["User-Agent"]
EOT
is $resp, "new-h2o_mruby_test", "H2O::Request#headers_in test";

$resp = fetch_header(<< 'EOT');
        mruby.handler: |
          r = H2O::Request.new
          r.headers_out["new-header"] = "h2o-mruby"
          # pass to next handler
          nil
        file.dir: examples/doc_root
EOT
like $resp, qr/^new-header:.*\Wh2o-mruby\W/im, "H2O::Response#headers_out test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O.return 404, "not found", "not found"
        file.dir: examples/doc_root
EOT
is $resp, "not found", "H2O.return with status code test";

($resp, $port)= fetch(<< 'EOT');
        mruby.handler: |
          H2O.return H2O::DECLINED
        file.dir: t/50mruby/
EOT
is $resp, "I'm index.html\n", "H2O.return with declined code test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O::Request.new.method
EOT
is $resp, "GET", "H2O::Request#method test";

$resp = fetch_uri(<< 'EOT', 'index.html?a=1');
        mruby.handler: |
          H2O::Request.new.query
EOT
is $resp, "?a=1", "H2O::Request#query test";

$resp = fetch_uri(<< 'EOT', 'index.html?a=1');
        mruby.handler: |
          H2O::Request.new.uri
EOT
is $resp, "/index.html?a=1", "H2O::Request#uri test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O::Request.new.authority
EOT
is $resp, "127.0.0.1:$port", "H2O::Request#authority test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O::Request.new.hostname
EOT
is $resp, "127.0.0.1", "H2O::Request#hostname test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O::Request.new.scheme
EOT
is $resp, "http", "H2O::Request#scheme test";

($resp, $port) = fetch(<< 'EOT');
        mruby.handler: |
          H2O::Connection.new.remote_ip
EOT
is $resp, "127.0.0.1", "H2O::Connection#remote_ip test";

$resp = fetch_uri(<< 'EOT', 'proxy.html');
        mruby.handler: |
          r = H2O::Request.new
          url = "http://#{r.authority}/"
          if r.uri == "/proxy.html"
            r.reprocess_request "#{url}/proxy/"
          end
        file.dir: t/50mruby/
EOT
is $resp, "I'm proxy.html\n", "H2O::Request#reprocess_request test";

subtest "server-push" => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          r = H2O::Request.new
          if r.uri == "/index.txt"
            r.http2_push_paths << "/index.js"
          end
          H2O.return H2O::DECLINED
        file.dir: t/assets/doc_root
EOT
    my $resp = `nghttp -n --stat https://127.0.0.1:$server->{tls_port}/index.txt`;
    like $resp, qr{\nresponseEnd\s.*\s/index\.js\n.*\s/index\.txt}is, "receives index.js then /index.txt";
};

subtest "infinite-reprocess" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "127.0.0.1:$port":
    paths:
      /:
        mruby.handler: |
          r = H2O::Request.new
          r.reprocess_request "http://127.0.0.1:$port/"
EOT
    });
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $stderr, qr{^HTTP\/1.1 502 }s, "502 response";
    like $stdout, qr{too many internal reprocesses}, "reason";
};

done_testing();
