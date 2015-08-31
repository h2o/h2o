use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "handler-file" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler-file: t/50mruby/hello.rb
EOT
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $body, "hello from h2o_mruby\n";
    like $headers, qr{^HTTP/1\.1 200 OK\r\n}s;
    like $headers, qr{^content-type: text/plain; charset=utf-8\r$}im;
};

subtest "basic" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /inline:
        mruby.handler: |
          h = "hello"
          m =  "from h2o_mruby"
          h + " " + m + "\n"
      /max-headers:
        mruby.handler: |
          H2O.max_headers.to_s
      /headers-in:
        mruby.handler: |
          r = H2O::Request.new
          ua = r.headers_in["User-Agent"]
          r.headers_in["User-Agent"] = "new-#{ua}"
          r.headers_in["User-Agent"]
      /headers-out:
        mruby.handler: |
          r = H2O::Request.new
          r.headers_out["new-header"] = "h2o-mruby"
          # pass to next handler
          nil
        file.dir: examples/doc_root
      /return-404:
        mruby.handler: |
          H2O.return 404, "not found", "not found"
        file.dir: examples/doc_root
      /fallthru:
        mruby.handler: |
          H2O.return H2O::DECLINED
        file.dir: t/50mruby/
      /method:
        mruby.handler: |
          H2O::Request.new.method
      /query:
        mruby.handler: |
          H2O::Request.new.query
      /uri:
        mruby.handler: |
          H2O::Request.new.uri
      /authority:
        mruby.handler: |
          H2O::Request.new.authority
      /hostname:
        mruby.handler: |
          H2O::Request.new.hostname
      /scheme:
        mruby.handler: |
          H2O::Request.new.scheme
      /remote_ip:
        mruby.handler: |
          H2O::Connection.new.remote_ip
      /status:
        mruby.handler: |
          H2O::Request.new.status
      /status/set-and-get:
        mruby.handler: |
          r = H2O::Request.new
          r.status = 401
          r.status
EOT
    my $fetch = sub {
        my $path = shift;
        run_prog("curl --silent -A h2o_mruby_test --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path");
    };
    my ($headers, $body) = $fetch->("/inline/");
    is $body, "hello from h2o_mruby\n", "inline";
    ($headers, $body) = $fetch->("/max-headers/");
    is $body, "100", "max_headers";
    ($headers, $body) = $fetch->("/headers-in/");
    is $body, "new-h2o_mruby_test", "headers_in";
    subtest "headers-out" => sub {
        ($headers, $body) = $fetch->("/headers-out/");
        like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
        like $headers, qr{^new-header: h2o-mruby\r$}im;
        is md5_hex($body), md5_file("examples/doc_root/index.html");
    };
    subtest "return-404" => sub {
        ($headers, $body) = $fetch->("/return-404/");
        like $headers, qr{^HTTP/1\.1 404 not found\r\n}is;
        is $body, "not found";
    };
    subtest "fallthru" => sub {
        ($headers, $body) = $fetch->("/fallthru/");
        like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
        is md5_hex($body), md5_file("t/50mruby/index.html");
    };
    is [$fetch->("/method/")]->[1], "GET", "method";
    is [$fetch->("/query/?a=1")]->[1], "?a=1", "method";
    is [$fetch->("/uri/?a=1")]->[1], "/uri/?a=1", "uri";
    is [$fetch->("/authority/")]->[1], "127.0.0.1:$server->{port}", "authority";
    is [$fetch->("/hostname/")]->[1], "127.0.0.1", "hostname";
    is [$fetch->("/scheme/")]->[1], "http", "scheme";
    is [$fetch->("/remote_ip/")]->[1], "127.0.0.1", "remote_ip";
    is [$fetch->("/status/")]->[1], "0", "status";
    is [$fetch->("/status/set-and-get/")]->[1], "401", "status";
};

subtest "reprocess_request" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          r = H2O::Request.new
          r.reprocess_request "/dest#{r.path}"
      /scheme-abs-path:
        mruby.handler: |
          r = H2O::Request.new
          r.reprocess_request "http:/dest#{r.path[16..-1]}"
      /dest/rel:
        mruby.handler: |
          r = H2O::Request.new
          r.reprocess_request "..#{r.path[9..-1]}"
      /dest:
        mruby.handler: |
          r = H2O::Request.new
          "#{r.scheme}://#{r.authority}#{r.path}"
      /abs:
        mruby.handler: |
          r = H2O::Request.new
          r.reprocess_request "https://vhost#{r.path[4..-1]}"
  vhost:
    paths:
      /:
        mruby.handler: |
          r = H2O::Request.new
          "#{r.scheme}://#{r.authority}#{r.path}"
EOT
    subtest "abs-path" => sub {
        my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        is $stdout, "http://default/dest/";
        ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/hoge");
        is $stdout, "http://default/dest/hoge";
    };
    subtest "scheme-abs-path" => sub {
        my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/scheme-abs-path/");
        is $stdout, "http://default/dest/";
        ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/scheme-abs-path/hoge");
        is $stdout, "http://default/dest/hoge";
    };
    subtest "rel-path" => sub {
        my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/dest/rel/");
        is $stdout, "http://default/dest/";
        ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/dest/rel/hoge");
        is $stdout, "http://default/dest/hoge";
    };
    subtest "abs" => sub {
        my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/abs/");
        is $stdout, "https://vhost/";
        ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/abs/hoge");
        is $stdout, "https://vhost/hoge";
    };
};

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

subtest "send-file" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /auto-content-type:
        mruby.handler: |
          r = H2O::Request.new
          r.send_file("t/50mruby/index.html")
      /explicit-content-type:
        mruby.handler: |
          r = H2O::Request.new
          r.headers_out["content-type"] = "text/plain"
          r.send_file("t/50mruby/index.html")
      /404:
        mruby.handler: |
          r = H2O::Request.new
          r.status = 404
          r.send_file("t/50mruby/index.html")
      /nonexistent:
        mruby.handler: |
          r = H2O::Request.new
          if !r.send_file("t/50mruby/nonexistent")
            r.status = 404
            "never mind!!!"
          end
EOT
    my $fetch = sub {
        my $path = shift;
        run_prog("curl --silent -A h2o_mruby_test --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path");
    };
    subtest "auto-content-type" => sub {
        my ($headers, $body) = $fetch->("/auto-content-type/");
        like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
        like $headers, qr{^content-type: text/html\r$}im;
        is md5_hex($body), md5_file("t/50mruby/index.html");
    };
    subtest "explicit-content-type" => sub {
        my ($headers, $body) = $fetch->("/explicit-content-type/");
        like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
        like $headers, qr{^content-type: text/plain\r$}im;
        is md5_hex($body), md5_file("t/50mruby/index.html");
    };
    subtest "404-page" => sub {
        my ($headers, $body) = $fetch->("/404/");
        like $headers, qr{^HTTP/1\.1 404 OK\r\n}is;
        like $headers, qr{^content-type: text/html\r$}im;
        is md5_hex($body), md5_file("t/50mruby/index.html");
    };
    subtest "nonexistent" => sub {
        my ($headers, $body) = $fetch->("/nonexistent/");
        like $headers, qr{^HTTP/1\.1 404 OK\r\n}is;
        like $headers, qr{^content-type: text/plain; charset=utf-8\r$}im;
        is $body, "never mind!!!";
    };
};

done_testing();
