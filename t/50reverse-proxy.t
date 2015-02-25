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
@{[ $h2o_keepalive ? "" : "        proxy.timeout.keepalive: 0" ]}
EOT
    };
    ok ! check_port($upstream_port), "upstream should be down now";
}

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
                like $resp, qr/^via: 1\.1 127\.0\.0\.1:$port$/mi, "via";
                $resp = `curl --silent --insecure --header 'X-Forwarded-For: 127.0.0.2' --header 'Via: 2 example.com' $proto://127.0.0.1:$port/echo-headers`;
                like $resp, qr/^x-forwarded-for: 127\.0\.0\.2, 127\.0\.0\.1$/mi, "x-forwarded-for (append)";
                like $resp, qr/^via: 2 example.com, 1\.1 127\.0\.0\.1:$port$/mi, "via (append)";
            };
        };
        $doit->('http', $port);
        $doit->('https', $tls_port);
    };

    subtest 'nghttp' => sub {
        plan skip_all => 'nghttp not found'
            unless prog_exists('nghttp');
        my $doit = sub {
            my ($proto, $opt, $port) = @_;
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
                plan skip_all => 'nghttp issues #161'
                    if $opt eq '-u';
                $out = `nghttp $opt -H 'cookie: a=b' -H 'cookie: c=d' $proto://127.0.0.1:$port/echo-headers`;
                like $out, qr{^cookie: a=b; c=d$}m;
            };
            subtest 'issues/185' => sub {
                my $out = `nghttp $opt -v "$proto://127.0.0.1:$port/set-headers?access-control-allow-origin=%2a"`;
                is $?, 0;
                like $out, qr/ access-control-allow-origin: \*$/m;
            };
            subtest 'issues/192' => sub {
                my $cookie = '_yohoushi_session=ZU5tK2FhcllVQ1RGaTZmZE9MUXozZnAzdTdmR250ZjRFU1hNSnZ4Y2JxZm9pYzJJSEpISGFKNmtWcW1HcjBySmUxZzIwNngrdlVIOC9jdmg0R3I3TFR4eVYzaHlFSHdEL1M4dnh1SmRCbVl3ZE5FckZEU1NyRmZveWZwTmVjcVV5V1JhNUd5REIvWjAwQ3RiT1ZBNGVMUkhiN0tWR0c1RzZkSVhrVkdoeW1lWXRDeHJPUW52NUwxSytRTEQrWXdoZ1EvVG9kak9aeUxnUFRNTDB4Vis1RDNUYWVHZm12bDgwL1lTa09MTlJYcGpXN2VUWmdHQ2FuMnVEVDd4c3l1TTJPMXF1dGhYcGRHS2U2bW9UaG0yZGIwQ0ZWVzFsY1hNTkY5cVFvWjNqSWNrQ0pOY1gvMys4UmRHdXJLU1A0ZTZQc3pSK1dKcXlpTEF2djJHLzUwbytwSnVpS0xhdFp6NU9kTDhtcmgxamVXMkI0Nm9Nck1rMStLUmV0TEdUeGFSTjlKSzM0STc3NTlSZ05ZVjJhWUNibkdzY1I1NUg4bG96dWZSeGorYzF4M2tzMGhKSkxmeFBTNkpZS09HTFgrREN4SWd4a29kamRxT3FobDRQZ2xMVUE9PS0tQUxSWU5nWmVTVzRoN09sS3pmUVM3dz09--3a411c0cf59845f0b8ccf61f69b8eb87aa1727ac; path=/; HttpOnly';
                my $cookie_encoded = $cookie;
                $cookie_encoded =~ s{([^A-Za-z0-9_])}{sprintf "%%%02x", ord $1}eg;
                $out = `nghttp $opt -v $proto://127.0.0.1:$port/set-headers?set-cookie=$cookie_encoded`;
                is $?, 0;
                like $out, qr/ set-cookie: $cookie$/m;
            };
        };
        subtest 'http (upgrade)' => sub {
            $doit->('http', '-u', $port);
        };
        subtest 'http (direct)' => sub {
            $doit->('http', '', $port);
        };
        subtest 'https' => sub {
            plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
                unless openssl_can_negotiate();
            $doit->('https', '', $tls_port);
        };
    };
}

done_testing;
