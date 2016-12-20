use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

sub doit {
    my ($cmd, $format, @expected) = @_;

    unlink "$tempdir/access_log";

    my $server = spawn_h2o(<< "EOT");
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
    access-log:
      format: "$format"
      path: $tempdir/access_log
EOT

    $cmd->($server);

    my @log = do {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open access_log:$!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };

    for (my $i = 0; $i != @expected; ++$i) {
        $expected[$i] = $expected[$i]->($server)
            if ref $expected[$i] eq 'CODE';
        like $log[$i], $expected[$i];
    }
}

subtest "custom-log" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent --referer http://example.com/ http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"',
        qr{^127\.0\.0\.1 - - \[[0-9]{2}/[A-Z][a-z]{2}/20[0-9]{2}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-][0-9]{4}\] "GET / HTTP/1\.1" 200 6 "http://example.com/" "curl/.*"$},
    );
};

subtest "strftime" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%{%Y-%m-%dT%H:%M:%S}t',
        qr{^20[0-9]{2}-(?:0[1-9]|1[012])-(?:[012][0-9]|3[01])T[0-9]{2}:[0-9]{2}:[0-9]{2}$},
    );
};

subtest "strftime-special" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%{msec_frac}t::%{usec_frac}t::%{sec}t::%{msec}t::%{usec}t',
        qr{^([0-9]{3})::(\1[0-9]{3})::([0-9]+)::\3\1::\3\2$},
    );
};

subtest "more-fields" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '\"%A:%p\"',
        sub { my $server = shift; qr{^\"127\.0\.0\.1:$server->{port}\"$} },
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
        qr{^GET::/::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
        qr{^GET::/query\?abc=d::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
    );
};

subtest 'timings' => sub {
    my $doit = sub {
        my $opts = shift;
        doit(
            sub {
                my $server = shift;
                system("curl $opts --silent --data helloworld http://127.0.0.1:$server->{port}/ > /dev/null");
                system("curl $opts --silent --insecure --data helloworld https://127.0.0.1:$server->{tls_port}/ > /dev/null");
            },
            '%{connect-time}x:%{request-header-time}x:%{request-body-time}x:%{response-time}x:%{request-total-time}x:%{duration}x:%{undefined}x',
            map { qr{^[0-9\.]+:[0-9\.]+:[0-9\.]+:[0-9\.]+:[0-9\.]+:[0-9\.]+:-$} } (1..2),
        );
    };
    subtest 'http1' => sub {
        $doit->("");
    };
    subtest 'http2' => sub {
        plan skip_all => "curl does not support HTTP/2"
            unless curl_supports_http2();
        $doit->("--http2");
    };
};

subtest 'header-termination (issue 462)' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{user-agent}i',
        qr{^foobar/1$},
    );
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{content-type}o',
        qr{^text/plain$},
    );
};

subtest 'extensions' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
            system("curl --silent --insecure @{[curl_supports_http2() ? ' --http1.1' : '']} https://127.0.0.1:$server->{tls_port}/ > /dev/null");
            if (prog_exists("nghttp")) {
                system("nghttp -n https://127.0.0.1:$server->{tls_port}/");
                system("nghttp -n --weight=22 https://127.0.0.1:$server->{tls_port}/");
            }
        },
        '%{connection-id}x %{ssl.protocol-version}x %{ssl.session-reused}x %{ssl.cipher}x %{ssl.cipher-bits}x %{http2.stream-id}x %{http2.priority.received}x',
        do {
            my @expected = (
                qr{^2 - - - - - -$}is,
                qr{^3 TLSv[0-9.]+ 0 \S+RSA\S+ (?:128|256) - -$}is,
            );
            if (prog_exists("nghttp")) {
                push @expected, +(
                    qr{^4 TLSv[0-9.]+ 0 \S+RSA\S+ (?:128|256) [0-9]*[13579] 0:[0-9]+:16}is,
                    qr{^5 TLSv[0-9.]+ 0 \S+RSA\S+ (?:128|256) [0-9]*[13579] 0:[0-9]+:22}is,
                );
            }
            @expected;
        },
    );
};

subtest 'error' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/fastcgi > /dev/null");
        },
        '%{error}x',
        qr{^\[lib/handler/fastcgi\.c\] connection failed:}s,
    );
};

done_testing;
