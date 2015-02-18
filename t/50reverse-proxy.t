use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => (stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt halfdome.jpg);

my $huge_file_size = 50 * 1024 * 1024; # should be larger than the mmap_backend threshold of h2o
my $huge_file = create_data_file($huge_file_size);
my $huge_file_md5 = md5_file($huge_file);

for my $i (0..7) {
    my $h2o_keepalive = $i & 1 ? 1 : 0;
    my $starlet_keepalive = $i & 2 ? 1 : 0;
    my $starlet_force_chunked = $i & 4 ? 1 : 0;
    my $upstream_port = empty_port();

    subtest "e2e (h2o:$h2o_keepalive, starlet: $starlet_keepalive, starlet-chunked: $starlet_force_chunked)" => sub {
        ok ! check_port($upstream_port), "upstream should be down now";

        local $ENV{FORCE_CHUNKED} = $starlet_force_chunked;
        my $guard = spawn_upstream($upstream_port, $starlet_keepalive ? +("--max-keepalive-reqs=100") : ());

        run_tests_with_conf($upstream_port, << "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.keepalive: @{[ $h2o_keepalive ? "ON" : "OFF" ]}
EOT
    };
    ok ! check_port($upstream_port), "upstream should be down now";
}

# should return 502 in case of upstream error
subtest 'upstream-down' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    my $upstream_port = empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my $port = $server->{port};
    my $res = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$port/ 2>&1 > /dev/null`;
    like $res, qr{^HTTP/1\.1 502 }, "502 response on upstream error";
};

sub spawn_upstream {
    my ($port, @extra) = @_;
    spawn_server(
        argv     => [
            qw(plackup -MPlack::App::File -s Starlet --keepalive-timeout 100 --access-log /dev/null -p), $port,
            @extra,
            ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready =>  sub {
            check_port($port);
        },
    );
}

sub run_tests_with_conf {
    my ($upstream_port, $h2o_conf) = @_;
    my $server = spawn_h2o($h2o_conf);
    my $port = $server->{port};
    my $tls_port = $server->{tls_port};

    subtest 'curl' => sub {
        plan skip_all => 'curl not found'
            unless prog_exists('curl');
        my $doit = sub {
            my ($proto, $port) = @_;
            for my $file (sort keys %files) {
                my $content = `curl --silent --show-error --insecure $proto://127.0.0.1:$port/$file`;
                is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
            }
            for my $file (sort keys %files) {
                my $content = `curl --silent --show-error --insecure --data-binary \@@{[ DOC_ROOT ]}/$file $proto://127.0.0.1:$port/echo`;
                is length($content), $files{$file}->{size}, "$proto://127.0.0.1/echo (POST, $file, size)";
                is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/echo (POST, $file, md5)";
            }
            for my $file (sort keys %files) {
                my $content = `curl --silent --show-error --insecure --header 'Transfer-Encoding: chunked' --data-binary \@@{[ DOC_ROOT ]}/$file $proto://127.0.0.1:$port/echo`;
                is length($content), $files{$file}->{size}, "$proto://127.0.0.1/echo (POST, chunked, $file, size)";
                is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/echo (POST, chunked, $file, md5)";
            }
            my $content = `curl --silent --show-error --insecure --data-binary \@$huge_file $proto://127.0.0.1:$port/echo`;
            is length($content), $huge_file_size, "$proto://127.0.0.1/echo (POST, mmap-backed, size)";
            is md5_hex($content), $huge_file_md5, "$proto://127.0.0.1/echo (POST, mmap-backed, md5)";
            $content = `curl --silent --show-error --insecure --header 'Transfer-Encoding: chunked' --data-binary \@$huge_file $proto://127.0.0.1:$port/echo`;
            is length($content), $huge_file_size, "$proto://127.0.0.1/echo (POST, chunked, mmap-backed, size)";
            is md5_hex($content), $huge_file_md5, "$proto://127.0.0.1/echo (POST, chunked, mmap-backed, md5)";
            subtest 'rewrite-redirect' => sub {
                $content = `curl --silent --insecure --dump-header /dev/stdout --max-redirs 0 $proto://127.0.0.1:$port/redirect/http://127.0.0.1:$upstream_port/abc`;
                like $content, qr{^location: $proto://127.0.0.1:$port/abc\r$}m;
            };
            subtest "x-forwarded ($proto)" => sub {
                my $resp = `curl --silent --insecure $proto://127.0.0.1:$port/echo-headers`;
                like $resp, qr/^x-forwarded-for: 127\.0\.0\.1$/mi, "x-forwarded-for";
                like $resp, qr/^x-forwarded-proto: $proto$/mi, "x-forwarded-proto";
                $resp = `curl --silent --insecure --header 'X-Forwarded-For: 127.0.0.2' $proto://127.0.0.1:$port/echo-headers`;
                like $resp, qr/^x-forwarded-for: 127\.0\.0\.2, 127\.0\.0\.1$/mi, "x-forwarded-for (append)";
            };
        };
        $doit->('http', $port);
        $doit->('https', $tls_port);
    };

    subtest 'nghttp' => sub {
        plan skip_all => 'nghttp not found'
            unless prog_exists('nghttp');
        my $doit = sub {
            my ($proto, $port) = @_;
            my $opt = $proto eq 'http' ? '-u' : '';
            for my $file (sort keys %files) {
                my $content = `nghttp $opt $proto://127.0.0.1:$port/$file`;
                is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
            }
            my $out = `nghttp $opt -H':method: POST' -d t/50reverse-proxy/hello.txt $proto://127.0.0.1:$port/echo`;
            is $out, "hello\n", "$proto://127.0.0.1/echo (POST)";
            $out = `nghttp $opt -m 10 $proto://127.0.0.1:$port/index.txt`;
            is $out, "hello\n" x 10, "$proto://127.0.0.1/index.txt x 10 times";
            $out = `nghttp $opt -H':method: POST' -d $huge_file $proto://127.0.0.1:$port/echo`;
            is length($out), $huge_file_size, "$proto://127.0.0.1/echo (mmap-backed, size)";
            is md5_hex($out), $huge_file_md5, "$proto://127.0.0.1/echo (mmap-backed, md5)";
            subtest 'cookies' => sub {
                $out = `nghttp $opt -H 'cookie: a=b' -H 'cookie: c=d' $proto://127.0.0.1:$port/echo-headers`;
                like $out, qr{^cookie: a=b; c=d$}m;
            };
        };
        subtest 'http' => sub {
            $doit->('http', $port);
        };
        subtest 'https' => sub {
            plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
                unless openssl_can_negotiate();
            $doit->('https', $tls_port);
        };
    };
}

done_testing;
