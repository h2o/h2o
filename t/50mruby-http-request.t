use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port check_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

sub create_upstream {
    my %opts = @_;
    my $upstream_hostport = $opts{upstream_hostport} || "127.0.0.1:@{[empty_port()]}";
    my @args = (
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen),
        $upstream_hostport,
    );
    if ($opts{keepalive}) {
        push(@args, qw(--max-keepalive-reqs 100));
    }
    push(@args, ASSETS_DIR . "/upstream.psgi");
    my $server = spawn_server(
        argv     => \@args,
        is_ready =>  sub {
            $upstream_hostport =~ /:([0-9]+)$/s
                or die "failed to extract port number";
            check_port($1);
        },
    );
    return ($server, $upstream_hostport);
};

subtest 'basic' => sub {
    my $upstream_hostport = "127.0.0.1:@{[empty_port()]}";
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
proxy.timeout.io: 1000
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            headers = {}
            env.each do |key, value|
              if /^HTTP_/.match(key)
                headers[\$'] = value
              end
            end
            headers["x-h2o-mruby"] = "1"
            http_request("http://$upstream_hostport#{env["PATH_INFO"]}#{env["QUERY_STRING"]}", {
              method: env["REQUEST_METHOD"],
              headers: headers,
              body: env["rack.input"],
            }).join
          end
      /as_str:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [http_request("http://$upstream_hostport/index.txt").join[2].join]]
          end
      /cl:
        mruby.handler: |
          Proc.new do |env|
            if !/^\\/([0-9]+)/.match(env["PATH_INFO"])
              raise "failed to parse PATH_INFO"
            end
            cl = \$1
            body = ["abc", "def", "ghi", "jkl", "mno"]
            if \$'.length != 0
              class T
                def initialize(a)
                  \@a = a
                end
                def each(&b)
                  \@a.each(&b)
                end
              end
              body = T.new(body)
            end
            [200, {"content-length" => cl}, body]
          end
      /esi:
        mruby.handler: |
          class ESIResponse
            def initialize(input)
              \@parts = input.split /(<esi:include +src=".*?" *\\/>)/
              \@parts.each_with_index do |part, index|
                if /^<esi:include +src=" *(.*?) *"/.match(part)
                  \@parts[index] = http_request("http://$upstream_hostport/#{\$1}")
                end
              end
            end
            def each(&block)
              \@parts.each do |part|
                if part.kind_of? String
                  block.call(part)
                else
                  part.join[2].each(&block)
                end
              end
            end
          end
          Proc.new do |env|
            resp = http_request("http://$upstream_hostport/esi.html").join
            resp[2] = ESIResponse.new(resp[2].join)
            resp
          end
      /partial:
        mruby.handler: |
          class PartialBody
            def initialize(body)
              \@body = body
            end
            def each
             \@body.each {|buf|
               if \@first_received
                 yield buf
               else
                 \@first_received = true
               end
             }
            end
          end
          Proc.new do |env|
            resp = http_request("http://$upstream_hostport/streaming-body").join
            [resp[0], resp[1], PartialBody.new(resp[2])]
          end
      /async-delegate:
        mruby.handler: |
          Proc.new do |env|
            resp = http_request("http://$upstream_hostport#{env["PATH_INFO"]}").join
            if resp[0] != 200
              resp = [399, {}, []]
            end
            resp
          end
        mruby.handler: |
          Proc.new do |env|
            [200, {}, ["delegated!"]]
          end
EOT
    });
    
    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        $curl_cmd .= ' --silent --dump-header /dev/stderr';
        subtest "connection-error" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/index.txt");
            like $headers, qr{HTTP/[^ ]+ 500\s}is;
        };
        my ($upstream) = create_upstream(upstream_hostport => $upstream_hostport);
        subtest "get" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/index.txt");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, "hello\n";
        };
        subtest "headers" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/echo-headers");
            like $headers, qr{^HTTP/[^ ]+ 200\s}is;
            like $body, qr{^host: $upstream_hostport$}im;
            unlike $body, qr{^host: 127.0.0.1:$port$}im;
            like $body, qr{^user-agent: *curl/}im;
            like $body, qr{^accept: *\*/\*$}im;
            like $body, qr{^x-h2o-mruby:}im;
        };
        subtest "post" => sub {
            my ($headers, $body) = run_prog("$curl_cmd --data 'hello world' $proto://127.0.0.1:$port/echo");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, 'hello world';
        };
        subtest "slow-chunked" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/streaming-body");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, (join "", 1..30);
        };
        subtest "as_str" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/as_str/");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, "hello\n";
        };
        subtest "content-length" => sub {
            subtest "non-chunked" => sub {
                for my $i (0..15) {
                    subtest "cl=$i" => sub {
                        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/cl/$i");
                        like $headers, qr{^HTTP/[^ ]+ 200\s.*\ncontent-length:\s*$i\r}is;
                        is $body, substr "abcdefghijklmno", 0, $i;
                    }
                };
                for my $i (16..30) {
                    subtest "cl=$i" => sub {
                        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/cl/$i");
                        like $headers, qr{^HTTP/[^ ]+ 200\s.*\ncontent-length:\s*15\r}is;
                        is $body, "abcdefghijklmno";
                    }
                };
            };
            subtest "chunked" => sub {
                for my $i (0..30) {
                    subtest "cl=$i" => sub {
                        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/cl/$i/chunked");
                        like $headers, qr{^HTTP/[^ ]+ 200\s.*\ncontent-length:\s*$i\r}is;
                        is $body, substr "abcdefghijklmno", 0, $i;
                    }
                };
            };
        };
        subtest "esi" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/esi/");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, "Hello to the world, from H2O!\n";
        };
        subtest "partial" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/partial/");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, join "", 2..30;
        };
        subtest "async-delegate" => sub {
            subtest "non-delegated" => sub {
                my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/async-delegate/index.txt");
                like $headers, qr{HTTP/[^ ]+ 200\s}is;
                is $body, "hello\n";
            };
            subtest "delegated" => sub {
                my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/async-delegate/notfound");
                like $headers, qr{HTTP/[^ ]+ 200\s}is;
                is $body, "delegated!";
            };
        };
    });
};

subtest 'cache-response' => sub {
    my ($upstream, $upstream_hostport) = create_upstream();
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  default:
    paths:
      /cache-response:
        mruby.handler: |
          resp = http_request("http://$upstream_hostport/index.txt").join
          resp[2] = [resp[2].join]
          Proc.new do |env|
            resp
          end
EOT
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        $curl_cmd .= ' --silent --dump-header /dev/stderr';

        subtest "cache-response" => sub {
            my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/cache-response");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, "hello\n";
        };
    });
};

subtest 'double consume' => sub {
    my ($upstream, $upstream_hostport) = create_upstream();
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
num-threads: 1
hosts:
  default:
    paths:
      /check-alive:
        mruby.handler: proc { [200, {}, []] }
      /join-join:
        mruby.handler: |
          Proc.new do |env|
            resp = http_request("http://$upstream_hostport/index.txt").join
            resp[2].join
            resp[2].join
            [200, {}, []]
          end
      /join-chunked:
        mruby.handler: |
          Proc.new do |env|
            resp = http_request("http://$upstream_hostport/index.txt").join
            resp[2].join
            [200, {}, resp[2]]
          end
      /chunked-join:
        mruby.handler: |
          resp = nil
          Proc.new do |env|
            if resp
              resp[2].join
            else
              resp = http_request("http://$upstream_hostport/index.txt").join
            end
            [200, {}, resp[2]]
          end
      /chunked-chunked:
        mruby.handler: |
          resp = nil
          Proc.new do |env|
            resp ||= http_request("http://$upstream_hostport/index.txt").join
            [200, {}, resp[2]]
          end
EOT
    });

    my $tester = sub {
        local $Test::Builder::Level = $Test::Builder::Level + 1;
        my ($path, $expected) = @_;
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}$path");
        like $headers, qr{HTTP/[^ ]+ $expected\s}is;
    };

    subtest "join-join" => sub {
        $tester->('/join-join', 500);
        $tester->('/check-alive', 200);
    };
    subtest "join-chunked" => sub {
        $tester->('/join-chunked', 500);
        $tester->('/check-alive', 200);
    };
    subtest "chunked-join" => sub {
        $tester->('/chunked-join', 200);
        $tester->('/chunked-join', 500);
        $tester->('/check-alive', 200);
    };
    subtest "chunked-chunked" => sub {
        $tester->('/chunked-chunked', 200);
        $tester->('/chunked-chunked', 500);
        $tester->('/check-alive', 200);
    };
};

subtest 'empty body' => sub {
    my ($upstream, $upstream_hostport) = create_upstream();
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  default:
    paths:
      /no-content:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://$upstream_hostport/no-content").join
            resp[2] = [resp[2].join]
            resp
          }
      /head:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://$upstream_hostport/index.txt", { :method => 'HEAD' }).join
            resp[2] = [resp[2].join]
            resp
          }
EOT
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        $curl_cmd .= ' --silent --dump-header /dev/stderr';

        subtest "no content" => sub {
            my ($headers, $body) = run_prog("$curl_cmd -m 1 $proto://127.0.0.1:$port/no-content");
            like $headers, qr{HTTP/[^ ]+ 204\s}is;
            is $body, "";
        };

        subtest "head" => sub {
            my ($headers, $body) = run_prog("$curl_cmd -m 1 $proto://127.0.0.1:$port/head");
            like $headers, qr{HTTP/[^ ]+ 200\s}is;
            is $body, "";
        };
    });
};

subtest 'keep-alive (h2o <=> upstream)' => sub {
    my ($upstream, $upstream_hostport) = create_upstream(keepalive => 1);
    my $spawner = sub {
        my %opts = @_;
        spawn_h2o(<< "EOT");
@{[ $opts{keepalive} ? "" : "proxy.timeout.keepalive: 0" ]}
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            q = env['QUERY_STRING']
            headers = q.empty? ? nil : { 'Connection' => q }
            resp = http_request("http://$upstream_hostport/echo-remote-port", { :headers => headers }).join
            resp[1]['upstream-connection'] = resp[1]['connection'] || 'keep-alive'
            resp
          }
EOT
    };
    my $curl = 'curl --silent --dump-header /dev/stderr';

    subtest 'on' => sub {
        subtest "default" => sub {
            my $server = $spawner->(keepalive => 1);
            my ($headers, $body);

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/");
            like $headers, qr{^upstream-connection: keep-alive}im;
            my $remote_port = $body;

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?close");
            like $headers, qr{^upstream-connection: close}im;
            is $body, $remote_port
        };

        subtest "keep-alive" => sub {
            my $server = $spawner->(keepalive => 1);
            my ($headers, $body);

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?keep-alive");
            like $headers, qr{^upstream-connection: keep-alive}im;
            my $remote_port = $body;

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?close");
            like $headers, qr{^upstream-connection: close}im;
            is $body, $remote_port
        };

        subtest "close" => sub {
            my $server = $spawner->(keepalive => 1);
            my ($headers, $body);

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?close");
            like $headers, qr{^upstream-connection: close}im;
            my $remote_port = $body;

            ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?close");
            like $headers, qr{^upstream-connection: close}im;
            isnt $body, $remote_port
        };
    };

    subtest 'off' => sub {
        my $server = $spawner->(keepalive => 0);
        my ($headers, $body);

        ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?keep-alive");
        like $headers, qr{^upstream-connection: close}im;
        my $remote_port = $body;

        ($headers, $body) = run_prog("$curl http://127.0.0.1:$server->{port}/?close");
        like $headers, qr{^upstream-connection: close}im;
        isnt $body, $remote_port
    };
};

subtest 'keep-alive (client <=> h2o)' => sub {
    my $doit = sub {
        my ($path, $chunked) = @_;

        unlink "$tempdir/access_log";
        my ($upstream, $upstream_hostport) = create_upstream();
        my $server = spawn_h2o(<< "EOT");
num-threads: 1
access-log:
  format: "%{remote}p"
  path: $tempdir/access_log
hosts:
  default:
    paths:
      /shortcut:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://$upstream_hostport/halfdome.jpg").join
            headers = {}
            unless env['QUERY_STRING'] == '?chunked'
              headers['content-length'] = resp[1]['content-length']
            end
            [200, headers, resp[2]]
          }
      /no-shortcut:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://$upstream_hostport/halfdome.jpg").join
            headers = {}
            unless env['QUERY_STRING'] == '?chunked'
              headers['content-length'] = resp[1]['content-length']
            end
            [200, headers, Class.new do
              def initialize(body)
                \@body = body
              end
              def each
                \@body.each {|buf| yield buf }
              end
            end.new(resp[2])]
          }
EOT

        my $query = $chunked ? '?chunked' : '';
        my $url = "http://127.0.0.1:$server->{port}$path$query";
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr $url $url");
        undef $server->{guard}; # wait until the log gets emitted
        my @log = do {
            open my $fh, "<", "$tempdir/access_log" or die "failed to open access_log:$!";
            map { my $l = $_; chomp $l; $l } <$fh>;
        };
        is $log[0], $log[1];
    };

    subtest 'no-shortcut' => sub {
        subtest 'chunked' => sub {
            $doit->('/no-shortcut', 1);
        };
        subtest 'no-chunked' => sub {
            $doit->('/no-shortcut', 0);
        };
    };

    subtest 'shortcut' => sub {
        subtest 'chunked' => sub {
            $doit->('/shortcut', 1);
        };
        subtest 'no-chunked' => sub {
            $doit->('/shortcut', 0);
        };
    };
};

subtest 'timeout' => sub {
    subtest 'connect timeout' => sub {
        my $server = spawn_h2o(<< "EOT");
proxy.timeout.connect: 100
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://192.0.2.0/").join
            if warn = resp[1].delete('client-warning')
              [504, resp[1], ["client warning: #{warn}"]]
            else
              resp
            end
          }
EOT

        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        like $headers, qr{HTTP/[^ ]+ 504\s}is;
        is $body, 'client warning: connection timeout';
    };

    subtest 'first byte timeout' => sub {
        my ($upstream, $upstream_hostport) = create_upstream();
        my $server = spawn_h2o(<< "EOT");
proxy.timeout.first_byte: 100
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            resp = http_request("http://$upstream_hostport/sleep-and-respond?sleep=1").join
            if warn = resp[1].delete('client-warning')
              [504, resp[1], ["client warning: #{warn}"]]
            else
              resp
            end
          }
EOT

        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        like $headers, qr{HTTP/[^ ]+ 504\s}is;
        is $body, 'client warning: first byte timeout';
    };
};

done_testing();
