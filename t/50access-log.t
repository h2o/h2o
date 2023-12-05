use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Net::EmptyPort qw(check_port);
use JSON qw(decode_json);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;
plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'racy under valgrind' if $ENV{"H2O_VALGRIND"};

my $tempdir = tempdir(CLEANUP => 1);
my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

sub doit {
    my ($cmd, $args, $expected, $max_ssl_version) = @_;
    $args = { format => $args }
        unless ref $args;
    $max_ssl_version ||= 'TLSv1.3';

    unlink "$tempdir/access_log";

    my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });
    my $server = spawn_h2o({conf => <<"EOT", max_ssl_version => $max_ssl_version});
send-informational: all
num-threads: 1
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /fastcgi:
        fastcgi.connect:
          port: /nonexistent
          type: unix
        error-log.emit-request-errors: OFF
      /set-cookie:
        file.dir: @{[ DOC_ROOT ]}
        header.add: "set-cookie: a=b"
        header.add: "set-cookie: c=d"
        header.add: "cache-control: must-revalidate"
        header.add: "cache-control: no-store"
      /compress:
        file.dir: @{[ DOC_ROOT ]}
        compress: [gzip]
      /proxy:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
    access-log:
      format: '$args->{format}'
@{[$args->{escape} ? "      escape: $args->{escape}" : ""]}
      path: $tempdir/access_log
EOT

    $server->{quic_port} = $quic_port;
    $cmd->($server);

    undef $server->{guard}; # log will be emitted before the server exits

    my @log = do {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open access_log:$!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };

    local $Test::Builder::Level = $Test::Builder::Level + 1;
    for (my $i = 0; $i != @$expected; ++$i) {
        if (ref $expected->[$i] eq 'CODE') {
            $expected->[$i]->($log[$i], $server);
        } else {
            like $log[$i], $expected->[$i];
        }
    }
}

subtest "custom-log" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent --referer http://example.com/ http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"',
        [ qr{^127\.0\.0\.1 - - \[[0-9]{2}/[A-Z][a-z]{2}/20[0-9]{2}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-][0-9]{4}\] "GET / HTTP/1\.1" 200 6 "http://example.com/" "curl/.*"$} ],
    );
};

subtest "strftime" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%{%Y-%m-%dT%H:%M:%S}t',
        [ qr{^20[0-9]{2}-(?:0[1-9]|1[012])-(?:[012][0-9]|3[01])T[0-9]{2}:[0-9]{2}:[0-9]{2}$} ],
    );
};

subtest "strftime-special" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%{msec_frac}t::%{usec_frac}t::%{sec}t::%{msec}t::%{usec}t',
        [ qr{^([0-9]{3})::(\1[0-9]{3})::([0-9]+)::\3\1::\3\2$} ],
    );
};

subtest "more-fields" => sub {
    my $local_port = "";
    doit(
        sub {
            my $server = shift;
            my $resp = `curl --silent -w ',\%{local_port}' http://127.0.0.1:$server->{port}/`;
            like $resp, qr{,(\d+)$}s;
            $local_port = do { $resp =~ /,(\d+)$/s; $1 };
        },
        '"%A:%p" "%{local}p" "%{remote}p"',
        [
            sub {
                my($log, $server) = @_;
                like $log, qr{^\"127\.0\.0\.1:$server->{port}\" \"$server->{port}\" \"$local_port\"$};
            },
        ],
    );
};

subtest 'ltsv-related' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port} > /dev/null");
            system("curl --silent http://127.0.0.1:$server->{port}/query?abc=d > /dev/null");
        },
        '%m::%U%q::%H::%V::%v',
        [
            qr{^GET::/::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
            qr{^GET::/query\?abc=d::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
        ],
    );
};

subtest 'timings' => sub {
    # The path should take at least 0.050 sec in total.
    # See also 50reverse-proxy-timings.t for timing stats.
    my $path = "proxy/streaming-body?sleep=0.01&count=5";
    my $least_duration = 0.040; # 0.50 is too sensitive

    my $doit = sub {
        my ($opts, $expected_status_line, $expected_protocol) = @_;
        doit(
            sub {
                my ($server) = @_;
                my $port = $expected_protocol ne "HTTP/3" ? $server->{tls_port} : $server->{quic_port};
                my $resp = `$client_prog -k $opts 'https://127.0.0.1:$port/$path' 2>&1`;
                like $resp, $expected_status_line, "HTTP request for $expected_protocol";
            },
            {
                format => '{
                    "protocol":"%H"
                    , "connect-time":%{connect-time}x
                    , "request-total-time":%{request-total-time}x
                    , "request-header-time":%{request-header-time}x
                    , "request-body-time":%{request-body-time}x
                    , "process-time":%{process-time}x
                    , "response-time":%{response-time}x
                    , "duration":%{duration}x
                    , "total-time":%{total-time}x
                    , "proxy.idle-time":%{proxy.idle-time}x
                    , "proxy.connect-time":%{proxy.connect-time}x
                    , "proxy.request-time":%{proxy.request-time}x
                    , "proxy.process-time":%{proxy.process-time}x
                    , "proxy.response-time":%{proxy.response-time}x
                    , "proxy.total-time":%{proxy.total-time}x
                }',
                escape => 'json',
            },
            [
                sub {
                    my($log_json) = @_;
                    my $log = decode_json($log_json);

                    is $log->{"protocol"}, $expected_protocol;

                    cmp_ok $log->{"connect-time"}, ">", 0;
                    cmp_ok $log->{"request-total-time"}, ">=", 0;
                    cmp_ok $log->{"request-header-time"}, ">=", 0;
                    cmp_ok $log->{"request-body-time"}, ">=", 0;
                    cmp_ok $log->{"process-time"}, ">=", 0;
                    cmp_ok $log->{"response-time"}, ">=", $least_duration;
                    cmp_ok $log->{"total-time"}, ">=", $least_duration;
                    cmp_ok $log->{"duration"}, ">=", $least_duration;
                    cmp_ok $log->{"proxy.idle-time"}, ">=", 0;
                    cmp_ok $log->{"proxy.connect-time"}, ">", 0;
                    cmp_ok $log->{"proxy.request-time"}, ">=", 0;
                    cmp_ok $log->{"proxy.process-time"}, ">", 0;
                    cmp_ok $log->{"proxy.response-time"}, ">", $least_duration;
                    cmp_ok $log->{"proxy.total-time"}, ">", $least_duration;
                },
            ],
        );
    };
    subtest 'http1' => sub {
        $doit->("", qr{^HTTP/1\.1 200\b}ms, "HTTP/1.1");
    };
    subtest 'http2' => sub {
        $doit->("-2 100", qr{^HTTP/2 200\b}ms, "HTTP/2");
    };
    subtest 'http3' => sub {
        $doit->("-3 100", qr{^HTTP/3 200\b}ms, "HTTP/3");
    };
};

subtest 'header-termination (issue 462)' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{user-agent}i',
        [ qr{^foobar/1$} ],
    );
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{content-type}o',
        [ qr{^text/plain$} ],
    );
};

subtest 'extensions' => sub {
    for my $set ([ qw{TLSv1.2 \S+RSA\S+} ], [ qw{TLSv1.3 TLS_AES_(?:128|256)_GCM_SHA(?:256|384)} ]) {
        my $tlsver = $set->[0];
        my $cipher = $set->[1];
        subtest $tlsver => sub {
            plan skip_all => "openssl does not support tls 1.3"
                unless openssl_supports_tls13();
            doit(
                sub {
                    my $server = shift;
                    sleep 1; # ensure check_port's SYN_ACK is delivered to the server before that generated by curl
                    system("curl --silent http://localhost:$server->{port}/ > /dev/null");
                    system("curl --silent --insecure @{[curl_supports_http2() ? ' --http1.1' : '']} https://localhost:$server->{tls_port}/ > /dev/null");
                    system("curl --silent --insecure @{[curl_supports_http2() ? ' --http1.1' : '']} https://127.0.0.1:$server->{tls_port}/ > /dev/null");
                    if (prog_exists("nghttp")) {
                        system("nghttp -n https://localhost:$server->{tls_port}/");
                        system("nghttp -n --weight=22 https://localhost:$server->{tls_port}/");
                    }
                },
                '%{connection-id}x %{request-id}x %{ssl.protocol-version}x %{ssl.session-reused}x %{ssl.cipher}x %{ssl.cipher-bits}x %{ssl.server-name}x %{http2.stream-id}x %{http2.priority.received}x',
                do {
                    my @expected = (
                        qr{^2 1 - - - - - - -$}is,
                        qr{^3 1 $tlsver 0 $cipher (?:128|256) localhost - -$}is,
                        qr{^4 1 $tlsver 0 $cipher (?:128|256) - - -$}is,
                    );
                    if (prog_exists("nghttp")) {
                        my $check = sub {
                            my ($line, $re) = @_;
                            my $ok = $line =~ /$re/;
                            if ($ok) {
                                my ($req_id, $stream_id) = ($1, $2);
                                pass "basic";
                                is $req_id, $stream_id, "request-id";
                                ok $stream_id % 2 == 1, "stream ID is odd";
                            } else {
                                fail "basic";
                            }
                        };
                        push @expected, +(
                            sub {
                                $check->(shift, qr{^5 ([0-9]+) $tlsver 0 $cipher (?:128|256) localhost ([0-9]+) 0:[0-9]+:16}is);
                            },
                            sub {
                                $check->(shift, qr{^6 ([0-9]+) $tlsver 0 $cipher (?:128|256) localhost ([0-9]+) 0:[0-9]+:22}is);
                            },
                        );
                    }
                    \@expected;
                },
                $tlsver,
            );
        };
    }
};

subtest 'ssl-log' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent -k https://127.0.0.1:$server->{tls_port}/ > /dev/null");
        },
        '%{ssl.session-id}x',
        [ qr{^\S+$}s ],
        'TLSv1.2',
    );
};

subtest 'error' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/fastcgi > /dev/null");
        },
        '%{error}x',
        [ qr{^\[lib/handler/fastcgi\.c\] in request:127\.0\.0\.1:\d+/fastcgi:connection failed:}s ],
    );
};

subtest 'set-cookie' => sub {
    # set-cookie header is the only header to be concatenated with %{...}o, according to Apache
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/set-cookie/ > /dev/null");
        },
        '"%<{set-cookie}o" "%>{set-cookie}o" "%{set-cookie}o" "%{cache-control}o"',
        [ qr{^"-" "a=b, c=d" "a=b, c=d" "must-revalidate"$}s ],
    );
};

subtest 'escape' => sub {
    for my $i ([default => qr{^/\\xe3\\x81\\x82$}s], [apache => qr{^/\\xe3\\x81\\x82$}s], [json => qr{^/\\u00e3\\u0081\\u0082$}s]) {
        my ($escape, $expected) = @$i;
        subtest $escape => sub {
            doit(
                sub {
                    my $server = shift;
                    my $sock = IO::Socket::INET->new(
                        PeerAddr => '127.0.0.1',
                        PeerPort => $server->{port},
                        Proto    => 'tcp',
                    ) or die "failed to connect to host 127.0.0.1:@{[$server->{port}]}:$!";
                    syswrite $sock, "GET /\xe3\x81\x82 HTTP/1.0\r\n\r\n";
                    while (sysread($sock, my $buf, 1000) > 0) {}
                },
                $escape eq 'default' ? '%U' : { format => '%U', escape => $escape },
                [ $expected ],
            );
        };
    }
};

subtest "json-null" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        # single specifier surrounded by quotes that consist a string literal in JSON should be converted to `null` if the specifier
        # resolves to null
        { format => q{"%h" %l "%l" ''%l'' ''%l '' ''"%l"''}, escape => 'json' },
        [ qr{^"127\.0\.0\.1" null null null 'null ' '"null"'$} ],
    );
};

subtest 'compressed-body-size' => sub {
    my $doit = sub {
        my ($opts, $expected) = @_;
        doit(
            sub {
                my $server = shift;
                system("curl $opts --silent http://127.0.0.1:$server->{port}/compress/alice.txt > /dev/null");
            },
            '%b',
            [ qr{^$expected$} ],
        );
    };
    subtest 'http1' => sub {
        $doit->("", 1661);
        $doit->("-H 'Accept-Encoding: gzip'", 908); # it doesn't contain chunked encoding overhead (12)
    };
    subtest 'http2' => sub {
        plan skip_all => "curl does not support HTTP/2"
            unless curl_supports_http2();
        $doit->("--http2", 1661);
        $doit->("--http2 -H 'Accept-Encoding: gzip'", 908);
    };
};

subtest 'header-bytes' => sub {
    my @expected;
    my $push_expected = sub {
        my ($proto, $path, $http_ver, $body_size, $header_size) = @_;
        $http_ver = $http_ver == 257 ? "1.1" : $http_ver / 256; # convert $http_ver to textual notation
        push @expected, sub {
            my $log = shift;
            subtest "$path-$proto-$http_ver" => sub {
                my @cols = split / +/, $log;
                is $cols[0], $path, "path";
                is $cols[1], "HTTP/$http_ver", "http version";
                is $cols[2], 200, "status";
                is $cols[3], $body_size, "body size";
                cmp_ok $cols[4], '>=', $header_size->[0], "header size (lower bound)";
                cmp_ok $cols[4], '<=', $header_size->[1], "header size (upper bound)";
            };
        };
    };
    doit(
        sub {
            my $server = shift;
            my $run_clients = sub {
                my ($path, $body_size, $header_size) = @_;
                run_with_curl($server, sub {
                    my ($proto, $port, $cmd, $http_ver) = @_;
                    is system("$cmd --silent --referer http://example.com/ $proto://127.0.0.1:${port}$path > /dev/null"), 0, "run curl";
                    $push_expected->($proto, $path, $http_ver, $body_size, $header_size->{$http_ver});
                });
                subtest "http/3" => sub {
                    is system("$client_prog -3 100 -k https://127.0.0.1:$server->{quic_port}$path > /dev/null"), 0, "run h2o-httpclient";
                    $push_expected->("https", $path, 768, $body_size, $header_size->{768});
                };
            };
            subtest "/" => sub {
                $run_clients->("/", 6, +{
                    257 => [220, 250], # http/1.1
                    512 => [75, 105],  # http/2
                    768 => [65, 95],   # http/3
                });
            };
            subtest "proxy-early-hints" => sub {
                $run_clients->("/proxy/early-hints", 11, +{
                    257 => [185, 215], # http/1.1
                    512 => [60, 90],   # http/2
                    768 => [75, 105],  # http/3
                });
            };
        },
        '%U %H %s %b %{response-header-bytes}x',
        \@expected,
    );
};

done_testing;
