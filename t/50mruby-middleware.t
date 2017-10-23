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
    my ($port, $mode) = @_;
    my $server = $mode eq 'proxy'   ? 'Starlet' :
                 $mode eq 'fastcgi' ? 'FCGI' :
                          die "unknown mode: $mode";
    my @args = (
        qw(plackup -s), $server, qw(--keepalive-timeout 100 --access-log /dev/null --listen),
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
    local $SIG{ALRM} = sub { die };
    alarm(3);
    my ($hstr, $body) = eval { run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path") };
    my $timeout = !! $@;
    alarm(0);
    if ($timeout) {
        die "timeout";
    }
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
} } qw(index.txt halfdome.jpg);

sub doit {
    my ($mode, $file, $next, $opts) = @_;
    $opts ||= +{};

    my ($spawner, $path);
    if ($mode eq 'call') {
        $path = '';
        $spawner = sub {
            my $conf = shift;
            spawn_h2o(sub {
                my ($port, $tls_port) = @_;
            << "EOT";
hosts:
  "127.0.0.1:$port":
    paths:
      /live-check:
        - mruby.handler: |
            def modify_env(env)
            end
            proc {|env| [200, {}, []] }
      /:
$conf
        - $next
EOT
            });
        };
    } elsif ($mode eq 'reprocess') {
        $path = '/for-reprocess';
        $spawner = sub {
            my $conf = shift;
            spawn_h2o(sub {
                my ($port, $tls_port) = @_;
            << "EOT";
fastcgi.send-delegated-uri: ON
hosts:
  "127.0.0.1:$port":
    paths:
      /live-check:
        - mruby.handler: |
            def modify_env(env)
              env["SCRIPT_NAME"] = ""
            end
            proc {|env| [200, {}, []] }
      /:
        - header.add: "x-reprocessed: true"
        - $next
      /for-reprocess:
$conf
EOT
            });
        };
    } else {
        die "unexpected mode: $mode";
    }

    my $live_check = sub {
        my $server = shift;
        local $Test::Builder::Level = $Test::Builder::Level + 1;
        lives_ok {
            my ($status, $headers, $body) = get($server, '/live-check');
            is $status, 200, 'live status check';
        }, 'live check';
    };

    subtest 'modify response header' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env)
              resp[1]['foo'] = 'FOO'
              resp
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $headers->{'foo'}, 'FOO';
        is length($body), $files{$file}->{size};
        is md5_hex($body), $files{$file}->{md5};
        is $headers->{'x-reprocessed'}, 'true' if $mode eq 'reprocess';
        $live_check->($server);
    };

    subtest 'stream response body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env)
              resp
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $headers->{'Content-Length'} || '', '';
        is length($body), $files{$file}->{size};
        is md5_hex($body), $files{$file}->{md5};
        is $headers->{'x-reprocessed'}, 'true' if $mode eq 'reprocess';
        $live_check->($server);
    };

    subtest 'join response body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env)
              resp[2] = [resp[2].join]
              resp
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $headers->{'Content-Length'}, length($body);
        is length($body), $files{$file}->{size};
        is md5_hex($body), $files{$file}->{md5};
        is $headers->{'x-reprocessed'}, 'true' if $mode eq 'reprocess';
        $live_check->($server);
    };

    subtest 'discard response' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env)
              [200, {}, ['mruby']]
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $body, 'mruby';
        $live_check->($server);
    };

    subtest 'discard response and each' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              status, headers, body = H2O.app.$mode(env)
              [status, headers, Class.new do
                def each
                  yield 'mruby'
                end
              end.new]
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $body, 'mruby';
        $live_check->($server);
    };

    subtest 'wrapped body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              status, headers, body = H2O.app.$mode(env)
              [status, headers, Class.new do
                def initialize(body)
                  \@body = body
                end
                def each
                  \@body.each {|buf| yield buf }
                end
              end.new(body)]
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is length($body), $files{$file}->{size};
        is md5_hex($body), $files{$file}->{md5};
        is $headers->{'x-reprocessed'}, 'true' if $mode eq 'reprocess';
        $live_check->($server);
    };

    subtest 'multiple one-by-one' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp1 = H2O.app.$mode(env)
              content1 = resp1[2].join
              resp2 = H2O.app.$mode(env)
              content2 = resp2[2].join
              [200, {}, [Digest::MD5.hexdigest(content1), Digest::MD5.hexdigest(content2)]]
            }
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 200;
        is $body, $files{$file}->{md5} x 2;
        $live_check->($server);
    };

    subtest 'multiple concurrent' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
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
EOT
        my ($status, $headers, $body) = get($server, "$path/$file");
        is $status, 503;
        is $body, 'this stream is already canceled by following H2O.app.call';
    };

    if ($mode eq 'call') {
        subtest 'multi handlers' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '1'
              resp
            }
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.app.$mode(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '2'
              resp
            }
EOT
            my ($status, $headers, $body) = get($server, "$path/$file");
            is $status, 200;
            is length($body), $files{$file}->{size};
            is md5_hex($body), $files{$file}->{md5};
            is $headers->{'x-middleware-order'}, '21', 'middleware order';
            $live_check->($server);
        };
    }
}

subtest 'file' => sub {
    for my $mode (qw/call reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "file.dir: @{[ ASSETS_DIR ]}/doc_root");
                };
            }
        };
    }
};

subtest 'proxy' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'proxy');
    for my $mode (qw/call reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "proxy.reverse.url: http://127.0.0.1:$port/");
                };
            }
        };
    }
};

subtest 'fastcgi' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'fastcgi');
    for my $mode (qw/call reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "fastcgi.connect: $port", +{ remove_script_name => 1 });
                };
            }
        };
    }
};

subtest 'infinite reprocess' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths:
      /:
        - mruby.handler: |
            proc {|env|
              H2O.app.reprocess(env)
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
EOT
    });
    my ($status, $headers, $body) = get($server, '/one-by-one/index.txt');
    is $status, 502;
    is $body, "too many internal reprocesses";
};

done_testing();
