use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
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
    my ($proto, $port, $curl, $path, $req_headers, $data_file) = @_;

    # build curl command
    my @curl_cmd = ($curl);
    push(@curl_cmd, qw(--silent --dump-header /dev/stderr));
    push(@curl_cmd, map { ('-H', "'$_'") } @{ $req_headers || [] });
    push(@curl_cmd, "$proto://127.0.0.1:$port$path");
    push(@curl_cmd, '--data-binary', "\@$data_file") if $data_file;
    my $curl_cmd = join(' ', @curl_cmd);

    local $SIG{ALRM} = sub { die };
    alarm(3);
    my ($hstr, $body) = eval { run_prog($curl_cmd) };
    my $timeout = !! $@;
    alarm(0);
    if ($timeout) {
        die "timeout";
    }
    $hstr =~ s!HTTP/[0-9.]+ 100 Continue\r\n\r\n!!;
    my ($sline, @hlines) = split(/\r\n/, $hstr);
    unless (($sline || '') =~ m{^HTTP/[\d\.]+ (\d+)}) {
        die "failed to get $path: @{[$sline || '']}";
    }
    my $status = $1 + 0;
    my $headers = +{ map { split(': ', $_, 2) } @hlines };
    $headers = +{ map { lc($_) => $headers->{$_} } keys %$headers };
    return ($status, $headers, $body);
}

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    my $content = do {
         open my $fh, "<", $fn or die "failed to open file:$fn:$!";
         local $/;
         join '', <$fh>;
     };
    +($_ => { size => (stat $fn)[7], md5 => md5_hex($content), content => $content });
} } qw(index.txt halfdome.jpg);

sub doit {
    my ($mode, $file, $next, $opts) = @_;
    $opts ||= +{};

    my ($spawner, $path);
    if ($mode eq 'next') {
        $path = '';
        $spawner = sub {
            my $conf = shift;
            spawn_h2o(sub {
                my ($port, $tls_port) = @_;
            << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /live-check:
        - mruby.handler: |
            def modify_env(env)
            end
            proc {|env| [200, {}, []] }
      /:
$conf
        - $next
  "127.0.0.1:$tls_port":
    paths: *paths
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
    paths: &paths
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
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
            });
        };
    } else {
        die "unexpected mode: $mode";
    }

    my $live_check = sub {
        my ($proto, $port, $curl) = @_;
        local $Test::Builder::Level = $Test::Builder::Level + 1;
        lives_ok {
            my ($status, $headers, $body) = get($proto, $port, $curl, '/live-check');
            is $status, 200, 'live status check';
        }, 'live check';
    };
    my $reprocess_check = sub {
        my ($headers) = @_;
        return unless $mode eq 'reprocess';
        is $headers->{'x-reprocessed'}, 'true', 'reprocess check';
    };

    subtest 'modify response header' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env| 
              modify_env(env) 
              resp = H2O.$mode.call(env) 
              resp[1]['foo'] = 'FOO'
              resp
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $headers->{'foo'}, 'FOO';
            is length($body), $files{$file}->{size};
            is md5_hex($body), $files{$file}->{md5};
            $reprocess_check->($headers);
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'stream response body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.$mode.call(env)
              resp
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $headers->{'content-length'} || '', '';
            is length($body), $files{$file}->{size};
            is md5_hex($body), $files{$file}->{md5};
            $reprocess_check->($headers);
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'join response body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.$mode.call(env)
              resp[2] = [resp[2].join]
              resp
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $headers->{'content-length'}, length($body);
            is length($body), $files{$file}->{size};
            is md5_hex($body), $files{$file}->{md5};
            $reprocess_check->($headers);
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'discard response' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.$mode.call(env)
              [200, {}, ['mruby']]
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $body, 'mruby';
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'discard response and each' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              status, headers, body = H2O.$mode.call(env)
              [status, headers, Class.new do
                def each
                  yield 'mruby'
                end
              end.new]
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $body, 'mruby';
            $reprocess_check->($headers);
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'wrapped body' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              status, headers, body = H2O.$mode.call(env)
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
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is length($body), $files{$file}->{size};
            is md5_hex($body), $files{$file}->{md5};
            $reprocess_check->($headers);
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'multiple one-by-one calls' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp1 = H2O.$mode.call(env)
              content1 = resp1[2].join
              resp2 = H2O.$mode.call(env)
              content2 = resp2[2].join
              [200, {}, [Digest::MD5.hexdigest(content1), Digest::MD5.hexdigest(content2)]]
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $body, $files{$file}->{md5} x 2;
            $live_check->($proto, $port, $curl);
        });
    };

    subtest 'multiple concurrent calls' => sub {
        my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp1 = H2O.$mode.call(env)
              resp2 = H2O.$mode.call(env)
              content1 = resp1[2].join
              content2 = resp2[2].join
              [200, {}, [Digest::MD5.hexdigest(content1), Digest::MD5.hexdigest(content2)]]
            }
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
            is $status, 200;
            is $body, $files{$file}->{md5} x 2;
            $live_check->($proto, $port, $curl);
        });
    };

    if ($mode eq 'call') {
        subtest 'multiple handlers' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.$mode.call(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '1'
              resp
            }
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              resp = H2O.$mode.call(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '2'
              resp
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/$file");
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                is $headers->{'x-middleware-order'}, '21', 'middleware order';
                $live_check->($proto, $port, $curl);
            });
        };
    }

    if ($opts->{post}) {
        subtest 'pass rack.input' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              H2O.$mode.call(env)
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/echo", undef, "@{[ DOC_ROOT ]}/$file");
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $reprocess_check->($headers);
                $live_check->($proto, $port, $curl);
            });
        };

        subtest 'modify rack.input' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              original = env['rack.input']
              env['rack.input'] = Class.new do
                def initialize(original, suffix)
                  \@original = original
                  \@suffix = suffix
                  \@eos = false
                end
                def read
                  \@original.read + \@suffix
                end
                def gets
                  return nil if \@eos
                  if buf = \@original.gets
                     return buf
                  end
                  \@eos = true
                  \@suffix
                end
                def each
                  while buf = gets
                    yield buf
                  end
                end
                def rewind
                  raise 'not implemented'
                end
              end.new(original, 'suffix')
              H2O.$mode.call(env)
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/echo", undef, "@{[ DOC_ROOT ]}/$file");
                is $status, 200;
                is length($body), $files{$file}->{size} + length('suffix');
                is md5_hex($body), md5_hex($files{$file}->{content} . 'suffix');
                $reprocess_check->($headers);
                $live_check->($proto, $port, $curl);
            });
        };

        subtest 'rack.input with smaller content-length' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              env['HTTP_CONTENT_LENGTH'] = '3'
              H2O.$mode.call(env)
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/echo", undef, "@{[ DOC_ROOT ]}/$file");
                is $status, 200;
                is length($body), 3;
                is $body, substr($files{$file}->{content}, 0, 3);
                $reprocess_check->($headers);
                $live_check->($proto, $port, $curl);
            });
        };

        subtest 'rack.input with bigger content-length' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              env['HTTP_CONTENT_LENGTH'] = '999999999'
              H2O.$mode.call(env)
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/echo", undef, "@{[ DOC_ROOT ]}/$file");
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $reprocess_check->($headers);
                $live_check->($proto, $port, $curl);
            });
        };

        subtest 'read rack.input partially' => sub {
            my $server = $spawner->(<< "EOT");
        - mruby.handler: |
            proc {|env|
              modify_env(env)
              head = env['rack.input'].read(3)
              status, headers, body = H2O.$mode.call(env)
              content = body.join
              [status, headers, [head, content]]
            }
EOT
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "$path/echo", undef, "@{[ DOC_ROOT ]}/$file");
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                $reprocess_check->($headers);
                $live_check->($proto, $port, $curl);
            });
        };
    }
    else { pass; } # FIXME
}

subtest 'file' => sub {
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "file.dir: @{[ ASSETS_DIR ]}/doc_root", {});
                };
            }
        };
    }
};

subtest 'proxy' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'proxy');
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "proxy.reverse.url: http://127.0.0.1:$port/", { post => 1 });
                };
            }
        };
    }
};

subtest 'fastcgi' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'fastcgi');
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    doit($mode, $file, "fastcgi.connect: $port", +{ remove_script_name => 1, post => 1 });
                };
            }
        };
    }
};

# subtest 'infinite reprocess' => sub {
#     my $server = spawn_h2o(sub {
#         my ($port, $tls_port) = @_;
#         << "EOT";
# hosts:
#   "127.0.0.1:$port":
#     paths: &paths
#       /:
#         - mruby.handler: |
#             proc {|env|
#               H2O.reprocess.call(env)
#             }
#   "127.0.0.1:$tls_port":
#     paths: *paths
# EOT
#     });
#     run_with_curl($server, sub {
#         my ($proto, $port, $curl) = @_;
#         my ($status, $headers, $body) = get($proto, $port, $curl, '/');
#         is $status, 502;
#         is $body, "too many internal reprocesses";
#     });
# };

subtest 'preserve original request headers' => sub {
    my $tempdir = tempdir(CLEANUP => 1);
    my $access_log = "$tempdir/access.log";
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /:
        - mruby.handler: |
            proc {|env|
              env['HTTP_X_FOO'] = env['QUERY_STRING'] unless env['QUERY_STRING'].empty?
              H2O.next.call(env)
            }
        - mruby.handler: |
            proc {|env|
              [200, {}, [env['HTTP_X_FOO']]]
            }
  "127.0.0.1:$tls_port":
    paths: *paths
access-log:
  path: $access_log
  format: "%{x-foo}i"
EOT
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        truncate $access_log, 0;

        my ($status, $headers, $body);
        ($status, $headers, $body) = get($proto, $port, $curl, '/index.txt', ['X-Foo: FOO']);
        is $status, 200;
        is $body, 'FOO';
        ($status, $headers, $body) = get($proto, $port, $curl, '/index.txt?BAR', ['X-Foo: FOO']);
        is $status, 200;
        is $body, 'BAR';

        my @log = do {
            open my $fh, "<", "$tempdir/access.log" or die "failed to open access.log:$!";
            map { my $l = $_; chomp $l; $l } <$fh>;
        };
        is $log[0], 'FOO';
        is $log[1], 'FOO';
    });
};

subtest 'set and unset env' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /:
        - setenv: 
            foo: FOO
        - mruby.handler: |
            proc {|env|
              env.delete 'foo'
              env['bar'] = 'BAR'
              H2O.next.call(env)
            }
        - mruby.handler: |
            proc {|env|
              [200, {}, [(env.map {|k, v| k + ":" + String(v) + "\\n"}).join]]
            }
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;

        my ($status, $headers, $body) = get($proto, $port, $curl, '/');
        is $status, 200;
        unlike $body, qr{^foo:FOO$}m;
        like $body, qr{^bar:BAR$}m;
    });
};

done_testing();
