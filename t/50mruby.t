use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
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
    subtest "protocol" => sub {
        run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my $content = `$curl --silent --show-error $proto://127.0.0.1:$port/echo`;
                if ($curl =~ /http2/) {
                    like $content, qr{"SERVER_PROTOCOL":"HTTP/2"}, "SERVER_PROTOCOL";
                } else {
                    like $content, qr{"SERVER_PROTOCOL":"HTTP/1\.1"}, "SERVER_PROTOCOL";
                }
            });
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
    like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n.*\s/index\.txt}is, "receives index.js then /index.txt";
};

subtest "server-push / nopush" => sub {
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
            [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload; nopush"}.join()}, []]
          end
        file.dir: t/assets/doc_root
EOT
    my $resp = `nghttp -n --stat https://127.0.0.1:$server->{tls_port}/index.txt`;
    unlike $resp, qr{/index\.js}is, "receives only /index.txt";
    like $resp, qr{/index\.txt}is, "receives only /index.txt";
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

subtest "exception" => sub {
    my $server = spawn_h2o(<< 'EOT');
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          cnt = 0
          Proc.new do |env|
            cnt += 1
            if cnt % 2 != 0
              [200, {}, ["hello\n"]]
            else
              raise "error from rack"
            end
          end
EOT
    my $fetch = sub {
        run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}");
    };
    for (1..3) {
        my ($headers, $body) = $fetch->();
        like $headers, qr{^HTTP/1\.1 200 }is;
        is $body, "hello\n";
        ($headers, $body) = $fetch->();
        like $headers, qr{^HTTP/1\.1 500 }is;
    }
};

subtest "post" => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            body = []
            3.times do
              env["rack.input"].rewind
              body << env["rack.input"].read
              body << "\\n"
            end
            [200, {}, body]
          end
EOT
    my ($headers, $body) = run_prog("curl --silent --data 'hello' --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
    is $body, "hello\n" x 3;
};

subtest "InputStream#read-after-close" => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          prev_input = nil
          Proc.new do |env|
            if !prev_input
              prev_input = env["rack.input"]
              resp = "not cached"
            else
              begin
                prev_input.read
                resp = "must not seed this"
              rescue IOError => e
                resp = "got IOError"
              end
            end
            [200, {}, [resp]]
          end
EOT
    my ($headers, $body) = run_prog("curl --silent --data 'hello' --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
    is $body, "not cached";
    ($headers, $body) = run_prog("curl --silent --data 'hello' --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 OK\r\n}is;
    is $body, "got IOError";
};

subtest "header-concat" => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [env["HTTP_COOKIE"]]]
          end
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($headers, $body) = run_prog("$curl --silent -H 'cookie: a=b' -H 'cookie: c=d' --dump-header /dev/stderr $proto://127.0.0.1:$port/");
        like $headers, qr{^HTTP/\S+ 200}is;
        like $body, qr{^a=b;\s*c=d$}is;
    });
};

subtest "close-called" => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          is_open = false
          lambda do |env|
            if is_open
              return [500, {}, ["close not called"]]
            end
            is_open = true
            return [
              200,
              {},
              Class.new do
                def each
                  yield "hello"
                end
                define_method(:close) do
                  is_open = false
                end
              end.new,
            ]
          end
EOT
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello";
    ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello";
};

subtest "close-called-on-exception" => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          is_open = false
          lambda do |env|
            if is_open
              return [500, {}, ["close not called"]]
            end
            is_open = true
            return [
              200,
              {},
              Class.new do
                def each
                  yield "hello"
                  raise "yeah!"
                end
                define_method(:close) do
                  is_open = false
                end
              end.new,
            ]
          end
EOT
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello";
    ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200 }is;
    is $body, "hello";
};

subtest "log lineno" => sub {
    my $tester = sub {
        my ($name, $conf, $expected) = @_;

        subtest $name => sub {
            my $tempdir = tempdir(CLEANUP => 1);
            unlink "$tempdir/error_log";
            my $server = spawn_h2o(<< "EOT");
$conf
error-log: $tempdir/error_log
EOT
            run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            my @log = do {
                open my $fh, "<", "$tempdir/error_log"
                    or die "failed to open error_log:$!";
                map { my $l = $_; chomp $l; $l } <$fh>;
            };
            @log = grep { $_ =~ /^\[h2o_mruby\]/ } @log;
            like $log[$#log], qr{\[h2o_mruby\] in request:/:mruby raised: @{[$server->{conf_file}]}:$expected:\s*hoge \(RuntimeError\)};
        };
    };
    $tester->("flow style", <<"EOT", 5);
hosts:
  default:
    paths:
      /:
        mruby.handler: Proc.new do |env| raise "hoge" end
EOT
    $tester->("block style", <<"EOT", 7);
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            raise "hoge"
          end
EOT
};

subtest 'response with specific statuses should not contain content-length header' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            [204, {}, []]
          }
EOT
    my ($headers, $body) = run_prog("curl --silent --data 'hello' --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 204 OK\r\n}is;
    unlike $headers, qr{^content-length:}im;
};

subtest 'PATH_INFO and SCRIPT_NAME' => sub {
    plan skip_all => "nc not found"
        unless prog_exists("nc");

    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            [200, {}, ['handler1, ' + env['SCRIPT_NAME'] + ', ' + env['PATH_INFO']]]
          }
      /abc:
        mruby.handler: |
          proc {|env|
            [200, {}, ['handler2, ' + env['SCRIPT_NAME'] + ', ' + env['PATH_INFO']]]
          }
      "/foo bar":
        mruby.handler: |
          proc {|env|
            [200, {}, ['handler3, ' + env['SCRIPT_NAME'] + ', ' + env['PATH_INFO']]]
          }
EOT
    my $nc = sub {
        my $path = shift;
        my $cmd = "echo 'GET $path HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n\\r' | nc 127.0.0.1 $server->{port}";
        (undef, my $r) = run_prog($cmd);
        split(/\r\n\r\n/, $r, 2);
    };

    my $body;
    (undef, $body) = $nc->('/abc/def%20ghi');
    is $body, 'handler2, /abc, /def%20ghi', 'should be kept undecoded';

    (undef, $body) = $nc->('/abc/def/../ghi/../jhk');
    is $body, 'handler2, /abc, /def/../ghi/../jhk', 'https://github.com/h2o/h2o/pull/1480#issuecomment-339614160';

    (undef, $body) = $nc->('/123/../abc/def/../ghi');
    is $body, 'handler2, /abc, /def/../ghi', 'https://github.com/h2o/h2o/pull/1480#issuecomment-339658134';

    (undef, $body) = $nc->('/foo%20bar/baz');
    is $body, 'handler3, /foo bar, /baz', 'paths should be decoded';

    (undef, $body) = $nc->('/xxx/../hoge');
    is $body, 'handler1, , /xxx/../hoge', 'string size is too big issue 1';

    (undef, $body) = $nc->('/../abc');
    is $body, 'handler2, /abc, ', 'string size is too big issue 2';

    (undef, $body) = $nc->('abc');
    is $body, 'handler2, /abc, ', 'no leading slash 1';

    (undef, $body) = $nc->('abc/def');
    is $body, 'handler2, /abc, /def', 'no leading slash 2';

    (undef, $body) = $nc->('123/../abc/def/../ghi');
    is $body, 'handler2, /abc, /def/../ghi', 'no leading slash 3';

    (undef, $body) = $nc->('xyz');
    is $body, 'handler1, , xyz', 'no leading slash 4';

    (undef, $body) = $nc->('');
    is $body, 'handler1, , ', 'empty path';
};

done_testing();
