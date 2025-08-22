use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use Test::Exception;
use Hash::MultiValue;
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
        ASSETS_DIR . "/50mruby-middleware.psgi",
    );
    spawn_server(
        argv     => \@args,
        is_ready =>  sub { check_port($port) },
    );
};

sub get {
    my ($proto, $port, $curl, $path, $opts) = @_;
    $opts ||= +{};

    # build curl command
    my @curl_cmd = ($curl);
    push(@curl_cmd, qw(--silent --show-error --dump-header /dev/stderr));
    push(@curl_cmd, map { ('-H', "'$_'") } @{ $opts->{headers} || [] });
    push(@curl_cmd, "$proto://127.0.0.1:$port$path");
    push(@curl_cmd, '--data-binary', "\@$opts->{data_file}") if $opts->{data_file};
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
    ($hstr, my $curl_warnings) = split(/\r\n\r\n/, $hstr, 2);
    diag "Warning: $curl_warnings" if $curl_warnings;
    my ($sline, @hlines) = split(/\r\n/, $hstr);
    chomp($sline //= '');
    unless ($sline =~ m{^HTTP/[\d\.]+ (\d+)}) {
        diag("failed to get `$curl_cmd`: @{[ $sline // '' ]}");
        return (499, Hash::MultiValue->new, "");
    }
    my $status = $1 + 0;
    my $headers = Hash::MultiValue->new(map { (lc($_->[0]), $_->[1]) } map { [ split(': ', $_, 2) ] } @hlines);
    # unless ($opts->{list_headers}) {
    #     $headers = +{ @$headers };
    # }
    # my $headers = +{ map { split(': ', $_, 2) } @hlines };
    # $headers = +{ map { lc($_) => $headers->{$_} } keys %$headers };
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

sub into_path {
    my ($testname) = @_;
    $testname =~ s/[^a-z0-9]/-/g;
    return '/' . $testname;
}

my @testcases = (
    +{
        name => 'modify response header',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env| 
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env) 
              resp[1]['foo'] = 'FOO'
              resp
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $headers->{'foo'}, 'FOO';
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'content-length response body',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env)
              resp
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $headers->{'content-length'} || '', $files{$file}->{size};
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'stream response body',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env)
              resp[1].delete 'content-length'
              resp
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $headers->{'content-length'} || '', '';
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'join response body',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env)
              resp[2] = [resp[2].join]
              resp
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $headers->{'content-length'}, length($body);
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'discard response',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env)
              [200, {}, ['mruby']]
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $body, 'mruby';
                live_check($server);
            });
        },
    },
    +{
        name => 'discard response and each',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              status, headers, body = H2O.$mode.call(env)
              headers.delete('content-length')
              [status, headers, Class.new do
                def each
                  yield 'mruby'
                end
              end.new]
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $body, 'mruby';
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'wrapped body',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
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
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'multiple one-by-one calls',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp1 = H2O.$mode.call(env)
              content1 = resp1[2].join
              resp2 = H2O.$mode.call(env)
              content2 = resp2[2].join
              [200, {}, [Digest::MD5.hexdigest(content1), Digest::MD5.hexdigest(content2)]]
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $body, $files{$file}->{md5} x 2;
                live_check($server);
            });
        },
    },
    +{
        name => 'multiple concurrent calls',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp1 = H2O.$mode.call(env)
              resp2 = H2O.$mode.call(env)
              content1 = resp1[2].join
              content2 = resp2[2].join
              [200, {}, [Digest::MD5.hexdigest(content1), Digest::MD5.hexdigest(content2)]]
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $body, $files{$file}->{md5} x 2;
                live_check($server);
            });
        },
    },
    +{
        name => 'multiple handlers',
        mode => 'next',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '1'
              resp
            }
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              resp = H2O.$mode.call(env);
              resp[1]['x-middleware-order'] ||= ''
              resp[1]['x-middleware-order'] += '2'
              resp
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                is $headers->{'x-middleware-order'}, '21', 'middleware order';
                live_check($server);
            });
        },
    },
    +{
        name => 'pass rack.input',
        when => 'post',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              H2O.$mode.call(env)
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/echo", +{ %$gopts, data_file => "@{[ DOC_ROOT ]}/$file" });
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'modify rack.input',
        when => 'post',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              env.delete('CONTENT_LENGTH')
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
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/echo", +{ %$gopts, data_file => "@{[ DOC_ROOT ]}/$file" });
                is $status, 200;
                is length($body), $files{$file}->{size} + length('suffix');
                is md5_hex($body), md5_hex($files{$file}->{content} . 'suffix');
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'rack.input with smaller content-length',
        when => 'post',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              env['CONTENT_LENGTH'] = '3'
              H2O.$mode.call(env)
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/echo", +{ %$gopts, data_file => "@{[ DOC_ROOT ]}/$file" });
                is $status, 200;
                is length($body), 3;
                is $body, substr($files{$file}->{content}, 0, 3);
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'rack.input with bigger content-length',
        when => 'post',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              env['CONTENT_LENGTH'] = '999999999'
              H2O.$mode.call(env)
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/echo", +{ %$gopts, data_file => "@{[ DOC_ROOT ]}/$file" });
                is $status, 200;
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'read rack.input partially',
        when => 'post',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              head = env['rack.input'].read(3)
              H2O.$mode.call(env)
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/echo", +{ %$gopts, data_file => "@{[ DOC_ROOT ]}/$file" });
                is $status, 200;
                is length($body), $files{$file}->{size} - 3;
                is md5_hex($body), md5_hex(substr($files{$file}->{content}, 3));
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'response shortcut',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              H2O.$mode.request(env)
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $headers->{'content-length'}, length($body);
                is length($body), $files{$file}->{size};
                is md5_hex($body), $files{$file}->{md5};
                reprocess_check($headers, $mode);
                live_check($server);
            });
        },
    },
    +{
        name => 'discard request',
        handler => sub { my $mode = shift; <<"EOT" },
        - mruby.handler: |
            proc {|env|
              modify_env(env, '$mode')
              req = H2O.$mode.request(env)
              [200, {}, ['mruby']]
            }
EOT
        test => sub {
            my ($server, $tc, $mode, $file, $gopts) = @_;
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($status, $headers, $body) = get($proto, $port, $curl, "@{[ into_path($tc->{name})]}/$file", $gopts);
                is $status, 200;
                is $body, 'mruby';
                live_check($server);
            });
        },
    },
);

sub create_h2o {
    my ($next) = @_;

    my $gen_pathconf = sub {
        my ($tc, $mode) = @_;
        my $handler = $tc->{handler}->($mode);
        my $conf = <<"EOT";
      @{[ into_path($tc->{name}) ]}:
$handler
EOT
        if ($mode eq 'next') {
            $conf .= <<"EOT";
        - $next
EOT
        }
        return $conf;
    };

    my @filtered = grep { !$ENV{TESTCASE} || $ENV{TESTCASE} eq $_->{name} } @testcases;

    return spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
fastcgi.send-delegated-uri: ON
hosts:
  "livecheck.example.com":
    paths:
      /:
        - mruby.handler: |
            def modify_env(env, mode)
              env["SCRIPT_NAME"] = "" if mode == 'reprocess'
            end
            proc {|env| [200, {}, []] }
  "next.example.com":
    paths:
@{[ join("\n", map { $gen_pathconf->($_, 'next') } @filtered) ]}
  "reprocess.example.com":
    paths:
      /: # redirected endpoint from the handler
        - header.add: "x-reprocessed: true"
        - $next
@{[ join("\n", map { $gen_pathconf->($_, 'reprocess') } @filtered) ]}
EOT
    });
}

sub live_check {
    my ($server) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    lives_ok {
        my ($status, $headers, $body) = get('http', $server->{port}, 'curl', '/live-check', +{ headers => ['host: livecheck.example.com'] });
        is $status, 200, 'live status check';
    } 'live check';
}

sub reprocess_check {
    my ($headers, $mode) = @_;
    return unless $mode eq 'reprocess';
    is $headers->{'x-reprocessed'}, 'true', 'reprocess check';
}

sub run_testcases {
    my ($server, $mode, $file, $opts) = @_;
    $opts ||= +{};

    my $gopts = +{ headers => ["host: $mode.example.com"] };
    for my $tc (@testcases) {
        subtest $tc->{name} => sub {
            plan skip_all => '' if $ENV{TESTCASE} && $ENV{TESTCASE} ne $tc->{name};
            plan skip_all => '' if $tc->{when} && !$opts->{$tc->{when}};
            plan skip_all => '' if $tc->{mode} && $mode ne $tc->{mode};
            $tc->{test}->($server, $tc, $mode, $file, $gopts);
        };
    }
}

subtest 'file' => sub {
    my $server = create_h2o("file.dir: @{[ ASSETS_DIR ]}/doc_root");
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    run_testcases($server, $mode, $file, {});
                };
            }
        };
    }
};

subtest 'proxy' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'proxy');
    my $server = create_h2o("proxy.reverse.url: http://127.0.0.1:$port/");
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    run_testcases($server, $mode, $file, { post => 1 });
                };
            }
        };
    }
};

subtest 'fastcgi' => sub {
    my $port = empty_port();
    my $guard = create_upstream($port, 'fastcgi');
    my $server = create_h2o("fastcgi.connect: $port");
    for my $mode (qw/next reprocess/) {
        subtest $mode => sub {
            for my $file (keys %files) {
                subtest $file => sub {
                    run_testcases($server, $mode, $file, +{ post => 1 });
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
    paths: &paths
      /:
        - mruby.handler: |
            proc {|env|
              H2O.reprocess.call(env)
            }
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($status, $headers, $body) = get($proto, $port, $curl, '/');
        is $status, 502;
        is $body, "too many internal delegations";
    });
};

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
    truncate $access_log, 0;

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($status, $headers, $body);
        ($status, $headers, $body) = get($proto, $port, $curl, '/index.txt', +{ headers => ['X-Foo: FOO'] });
        is $status, 200;
        is $body, 'FOO';
        ($status, $headers, $body) = get($proto, $port, $curl, '/index.txt?BAR', +{ headers => ['X-Foo: FOO'] });
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

subtest 'modify SCRIPT_NAME' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /next:
        - mruby.handler: |
            proc {|env|
              env['SCRIPT_NAME'] = '/foo'
              H2O.next.call(env)
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
      /reprocess:
        - mruby.handler: |
            proc {|env|
              env['SCRIPT_NAME'] = '/foo'
              H2O.reprocess.call(env)
            }
      /foo:
        - mruby.handler: proc {|env| [200, {}, []] }
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;

        my ($status, $headers, $body);
        ($status, $headers, $body) = get($proto, $port, $curl, '/next');
        is $status, 500, 'next';
        ($status, $headers, $body) = get($proto, $port, $curl, '/reprocess');
        is $status, 200, 'reprocess';
    });
};

subtest 'non-blocking' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /blocking:
        - mruby.handler: |
            proc {|env|
              st = Time.now
              H2O.next.call(env)
              H2O.next.call(env)
              et = Time.now
              [200, {}, [et - st]]
            }
        - mruby.handler:  proc {|env| sleep 1; [200, {}, []] }
      /non-blocking:
        - mruby.handler: |
            proc {|env|
              st = Time.now
              req1 = H2O.next.request(env)
              req2 = H2O.next.request(env)
              req1.join
              req2.join
              et = Time.now
              [200, {}, [et - st]]
            }
        - mruby.handler:  proc {|env| sleep 1; [200, {}, []] }
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;

        my ($status, $headers, $body);
        ($status, $headers, $body) = get($proto, $port, $curl, '/blocking');
        cmp_ok $body, '>', 1.9;
        ($status, $headers, $body) = get($proto, $port, $curl, '/non-blocking');
        cmp_ok $body, '<', 1.1;
    });
};

subtest 'invalid env' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /modify:
        - mruby.handler: |
            proc {|env|
              env.merge!(env['QUERY_STRING'].split('&').map {|p| p.split('=') }.to_h)
              H2O.next.call(env)
            }
        - file.dir: @{[DOC_ROOT]}
      /delete:
        - mruby.handler: |
            proc {|env|
              env.delete(env['QUERY_STRING'])
              H2O.next.call(env)
            }
        - file.dir: @{[DOC_ROOT]}
EOT
    map {
        my $path = $_;
        subtest $path => sub {
            my ($status) = get('http', $server->{port}, 'curl', $path);
            is $status, 500;
        };
    } qw(
        /delete?REQUEST_METHOD
        /delete?rack.url_scheme
        /delete?SCRIPT_NAME
        /delete?PATH_INFO
        /delete?QUERY_STRING
        /modify?CONTENT_LENGTH=foo
        /modify?h2o.remaining_delegations=foo
        /modify?h2o.remaining_reprocesses=foo
        /modify?REQUEST_METHOD=
        /modify?rack.url_scheme=
        /modify?SCRIPT_NAME=foo
        /modify?PATH_INFO=foo
        /modify?SCRIPT_NAME=/bar
    );
};

subtest 'do not apply filters multiple times' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /:
        - mruby.handler: |
            proc {|env|
              H2O.next.call(env)
            }
        - file.dir: @{[ ASSETS_DIR ]}/doc_root
        - header.add: "x-foo: FOO"
  "127.0.0.1:$tls_port":
    paths: *paths
EOT
    });
    my ($status, $headers, $body);
    ($status, $headers, $body) = get('http', $server->{port}, 'curl', '/');
    is scalar(my @v = $headers->get_all('x-foo')), 1;
};

subtest 'H2O.reprocess prefers internal reprocess' => sub {
    # internal reprocess preserves original env while external (i.e. proxying) reprocess doesn't
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  default:
    paths:
      /from:
        - setenv:
            "foo": "bar"
        - mruby.handler: |
            proc {|env|
              env['SCRIPT_NAME'] = '/to'
              H2O.reprocess.call(env)
            }
      /to:
        - mruby.handler: |
            proc {|env|
              [200, {}, [env["foo"]]]
            }
EOT
    });
    my ($status, $headers, $body);
    ($status, $headers, $body) = get('http', $server->{port}, 'curl', '/from');
    is $body, 'bar';
};

subtest 'both H2O.next and H2O.reprocess preserve content-type header' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
hosts:
  default:
    paths:
      /1:
        - mruby.handler: |
            proc {|env|
              H2O.next.call(env)
            }
        - mruby.handler: |
            proc {|env|
              next_ct = "#{env['CONTENT_TYPE']}1"
              env['NEXT_CT'] = next_ct
              env['SCRIPT_NAME'] = "/2"
              H2O.reprocess.call(env)
            }
      /2:
        # there was a bug that CONTENT_TYPE is unexpectedly added to env, not headers
        # so unset env here to check that the header is correctly forwarded as a header
        - unsetenv:
          - CONTENT_TYPE
        - mruby.handler: |
            proc {|env|
              reprocess_ct = "#{env['CONTENT_TYPE']}2"
              [200, {}, [env['NEXT_CT'], reprocess_ct]]
            }
EOT
    });
    my ($status, $headers, $body);
    ($status, $headers, $body) = get('http', $server->{port}, 'curl', '/1', +{ headers => ['content-type: OK'] });
    is $body, 'OK1OK2';
};

subtest 'headers with same name' => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << 'EOT';
hosts:
  default:
    paths:
      /next:
      - mruby.handler: |
          proc {|env|
            env['HTTP_FROM_FRONT'] = ['front1', 'front2']
            H2O.next.call(env)
          }
      - mruby.handler: |
          proc {|env|
            [
              200,
              {'from-back' => ['back1', 'back2'], 'set-cookie' => ['x=1', 'y=2']},
              [[
                env['HTTP_FROM_CLIENT'],
                env['HTTP_COOKIE'],
                env['HTTP_FROM_FRONT'],
              ].join("\n")],
            ]
          }
      /reprocess:
      - mruby.handler: |
          proc {|env|
            env['SCRIPT_NAME'] = '/reprocess/back'
            env['HTTP_FROM_FRONT'] = ['front1', 'front2']
            H2O.reprocess.call(env)
          }
      /reprocess/back:
      - mruby.handler: |
          proc {|env|
            [
              200,
              {'from-back' => ['back1', 'back2'], 'set-cookie' => ['x=1', 'y=2']},
              [[
                env['HTTP_FROM_CLIENT'],
                env['HTTP_COOKIE'],
                env['HTTP_FROM_FRONT'],
              ].join("\n")],
            ]
          }
EOT
    });
    for my $subtest (qw(next reprocess)) {
        subtest $subtest => sub {
            my ($status, $headers, $body) =
                get('http', $server->{port}, 'curl', "/$subtest",
                    +{headers => [
                        "from-client: client1",
                        "from-client: client2",
                        "cookie: a",
                        "cookie: b",
                    ]});
            is $status, 200, 'status';
            is_deeply [$headers->get_all('from-back')], ["back1, back2"], 'headers';
            is_deeply [$headers->get_all('set-cookie')], [qw(x=1 y=2)], 'set-cookie';
            is $body, "client1, client2\na; b\nfront1, front2", 'body';
        };
    }
};

done_testing();
