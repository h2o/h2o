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
          Proc.new do |env|
            [200, {}, ["hello from h2o_mruby\n"]]
          end
      /return-404:
        mruby.handler: |
          Proc.new do |env|
            [404, {}, ["not found"]]
          end
        file.dir: examples/doc_root
      /fallthru:
        mruby.handler: |
          Proc.new do |env|
            [399, {}, []]
          end
        file.dir: t/50mruby/
      /echo:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [JSON.generate(env)]]
          end
      /headers:
        mruby.handler: |
          Proc.new do |env|
            [200, {"foo" => "123\n456", "bar" => "baz"}, []]
          end
      /headers-each:
        mruby.handler: |
          Proc.new do |env|
            [200, [["content-type", "text/plain"], ["hello", "world"]], []]
          end
EOT
    my $fetch = sub {
        my $path = shift;
        run_prog("curl --silent -A h2o_mruby_test --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path");
    };
    my ($headers, $body) = $fetch->("/inline/");
    is $body, "hello from h2o_mruby\n", "inline";
    subtest "return-404" => sub {
        ($headers, $body) = $fetch->("/return-404/");
        like $headers, qr{^HTTP/1\.1 404 }is;
        is $body, "not found";
    };
    subtest "fallthru" => sub {
        ($headers, $body) = $fetch->("/fallthru/");
        like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
        is md5_hex($body), md5_file("t/50mruby/index.html");
    };
    subtest "echo" => sub {
        ($headers, $body) = $fetch->("/echo/abc?def");
        like $body, qr{"REQUEST_METHOD":"GET"}, "REQUEST_METHOD";
        like $body, qr{"SCRIPT_NAME":"/echo"}, "SCRIPT_NAME";
        like $body, qr{"PATH_INFO":"/abc"}, "PATH_INFO";
        like $body, qr{"QUERY_STRING":"def"}, "QUERY_STRING";
        like $body, qr{"SERVER_NAME":"default"}, "SERVER_NAME";
        like $body, qr{"SERVER_ADDR":"127.0.0.1"}, "SERVER_ADDR";
        like $body, qr{"SERVER_PORT":"$server->{port}"}, "SERVER_PORT";
        like $body, qr{"HTTP_HOST":"127.0.0.1:$server->{port}"}, "HTTP_HOST";
        like $body, qr{"SERVER_ADDR":"127.0.0.1"}, "REMOTE_ADDR";
        like $body, qr{"SERVER_PORT":"[0-9]+"}, "REMOTE_PORT";
        like $body, qr{"HTTP_USER_AGENT":"h2o_mruby_test"}, "HTTP_USER_AGENT";
        like $body, qr{"rack.url_scheme":"http"}, "url_scheme";
        like $body, qr{"SERVER_SOFTWARE":"h2o/[0-9]+\.[0-9]+\.[0-9]+}, "SERVER_SOFTWARE";
    };
    subtest "headers" => sub {
        ($headers, $body) = $fetch->("/headers/");
        like $headers, qr{^foo: 123\r$}mi;
        like $headers, qr{^foo: 456\r$}mi;
        like $headers, qr{^bar: baz\r$}mi;
    };
    subtest "headers-each" => sub {
        ($headers, $body) = $fetch->("/headers-each/");
        like $headers, qr{^content-type: text/plain\r$}mi;
        like $headers, qr{^hello: world\r$}mi;
    };
};

subtest "reprocess_request" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    reproxy: ON
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [200, {"x-reproxy-url" => "http://default/dest#{env["PATH_INFO"]}"}, ["should never see this"]]
          end
      /307:
        mruby.handler: |
          Proc.new do |env|
            [307, {"x-reproxy-url" => "http://default/dest#{env["PATH_INFO"]}"}, ["should never see this"]]
          end
      /dest:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, ["#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]};#{env["CONTENT_LENGTH"]}"]]
          end
EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "/dest/;";
    ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/hoge");
    is $stdout, "/dest/hoge;";
    subtest "preserve-method" => sub {
        ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/307/");
        is $stdout, "/dest/;";
        ($stderr, $stdout) = run_prog("curl --data hello --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/307/");
        is $stdout, "/dest/;5";
        ($stderr, $stdout) = run_prog("curl --data hello --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        is $stdout, "/dest/;";
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
          Proc.new do |env|
            push_paths = []
            if env["PATH_INFO"] == "/index.txt"
              push_paths << "/index.js"
            end
            [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join()}, []]
          end
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
        reproxy: ON
        mruby.handler: |
          Proc.new do |env|
            [200,{"x-reproxy-url" => "http://127.0.0.1:$port/"},[]]
          end
EOT
    });
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $stderr, qr{^HTTP\/1.1 502 }s, "502 response";
    like $stdout, qr{too many internal delegations}, "reason";
};

subtest "send-file" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [200,{}, File::open("t/50mruby/index.html")]
          end
EOT
    my ($headers, $body) = run_prog("curl --silent -A h2o_mruby_test --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
    is md5_hex($body), md5_file("t/50mruby/index.html");
};

done_testing();
