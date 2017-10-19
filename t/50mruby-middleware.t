use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port check_port);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

sub create_upstream {
    my ($port) = @_;
    my @args = (
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen),
        "127.0.0.1:$port",
        ASSETS_DIR . "/upstream.psgi",
    );
    spawn_server(
        argv     => \@args,
        is_ready =>  sub { check_port($port) },
    );
};

sub get {
  my ($server, $path) = @_;
  my ($hstr, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path");
  my ($sline, @hlines) = split(/\r\n/, $hstr);
  unless (($sline || '') =~ m{^HTTP/[\d\.]+ (\d+)}) {
    die "failed to get $path: @{[$sline || '']}";
  }
  my $status = $1 + 0;
  my $headers = +{ map { split(': ', $_, 2) } @hlines };
  return ($status, $headers, $body);
}

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => (stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt);
# } } qw(index.txt halfdome.jpg);

sub doit {
    my ($next) = @_;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /live-check:
        - mruby.handler: proc {|env| [200, {}, []] }

      /modify-response-header:
        - mruby.handler: |
            proc {|env|
              resp = H2O.app.call(env)
              resp[1]['foo'] = 'FOO'
              resp
            }
        - $next

      /stream-response-body:
        - mruby.handler: |
            proc {|env|
              resp = H2O.app.call(env)
              resp
            }
        - $next

      /join-response-body:
        - mruby.handler: |
            proc {|env|
              resp = H2O.app.call(env)
              resp[2] = [resp[2].join]
              resp
            }
        - $next

      /discard-response:
        - mruby.handler: |
            proc {|env|
              resp = H2O.app.call(env)
              [200, {}, ['mruby']]
            }
        - $next

      /discard-response-and-each:
        - mruby.handler: |
            proc {|env|
              resp = H2O.app.call(env)
              [200, {}, Class.new do
                def each
                  yield 'mruby'
                end
              end.new]
            }
        - $next

      /wrapped-body:
        - mruby.handler: |
            proc {|env|
              status, header, body = H2O.app.call(env)
              [200, {}, Class.new do
                def initialize(body)
                  \@body = body
                end
                def each
                  \@body.each {|buf| yield buf }
                end
              end.new(body)]
            }
        - $next
EOT
    my $live_check = sub {
        local $Test::Builder::Level = $Test::Builder::Level + 1;
        lives_ok {
            my ($status, $headers, $body) = get($server, '/live-check');
            is $status, 200, 'live status check';
        }, 'live check';
    };
    for my $file (sort keys %files) {
        subtest $file => sub {
            subtest 'modify response header' => sub {
                my ($status, $headers, $body) = get($server, "/modify-response-header/$file");
                is $status, 200;
                is $headers->{'foo'}, 'FOO';
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $live_check->();
            };

            subtest 'stream response body' => sub {
                my ($status, $headers, $body) = get($server, "/stream-response-body/$file");
                is $status, 200;
                is $headers->{'Content-Length'} || '', '';
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $live_check->();
            };

            subtest 'join response body' => sub {
                my ($status, $headers, $body) = get($server, "/join-response-body/$file");
                is $status, 200;
                is $headers->{'Content-Length'}, length($body);
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $live_check->();
            };

            subtest 'discard response' => sub {
                my ($status, $headers, $body) = get($server, "/discard-response/$file");
                is $status, 200;
                is $body, 'mruby';
                $live_check->();
            };

            subtest 'discard response and each' => sub {
                my ($status, $headers, $body) = get($server, "/discard-response-and-each/$file");
                is $status, 200;
                is $body, 'mruby';
                $live_check->();
            };

            subtest 'wrapped body' => sub {
                my ($status, $headers, $body) = get($server, "/wrapped-body/$file");
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $live_check->();
            };
        };
    }
}

subtest 'file' => sub {
    doit('file.dir: t/assets/doc_root');
};

subtest 'proxy' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port);
    doit("proxy.reverse.url: http://127.0.0.1:$port/");
};

subtest 'multiple calls' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /one-by-one:
        - mruby.handler: |
            proc {|env|
              resp1 = H2O.app.call(env)
              content1 = resp1[2].join
              resp2 = H2O.app.call(env)
              content2 = resp2[2].join
              [200, {}, [content1, content2]]
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
      /concurrent:
        - mruby.handler: |
            proc {|env|
              begin
                resp1 = H2O.app.call(env)
                resp2 = H2O.app.call(env)
                resp1[2].join
              rescue => e
                [503, {}, [e.message]]
              else
                [200, {}, []]
              end
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
EOT
    subtest 'one by one' => sub {
        my ($status, $headers, $body) = get($server, '/one-by-one/index.txt');
        is $status, 200;
        is $body, "hello\nhello\n";
    };
    subtest 'concurrent' => sub {
        my ($status, $headers, $body) = get($server, '/concurrent/index.txt');
        is $status, 503;
        is $body, 'this stream is already canceled by following H2O.app.call';
    };
};

subtest 'reprocess' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /one-by-one:
        - mruby.handler: |
            proc {|env|
              resp1 = H2O.app.call(env)
              content1 = resp1[2].join
              resp2 = H2O.app.call(env)
              content2 = resp2[2].join
              [200, {}, [content1, content2]]
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
      /concurrent:
        - mruby.handler: |
            proc {|env|
              begin
                resp1 = H2O.app.call(env)
                resp2 = H2O.app.call(env)
                resp1[2].join
              rescue => e
                [503, {}, [e.message]]
              else
                [200, {}, []]
              end
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
EOT
    subtest 'one by one' => sub {
        my ($status, $headers, $body) = get($server, '/one-by-one/index.txt');
        is $status, 200;
        is $body, "hello\nhello\n";
    };
    subtest 'concurrent' => sub {
        my ($status, $headers, $body) = get($server, '/concurrent/index.txt');
        is $status, 503;
        is $body, 'this stream is already canceled by following H2O.app.call';
    };
};

done_testing();
