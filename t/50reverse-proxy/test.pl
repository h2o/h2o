use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Getopt::Long;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use URI::Escape;
use t::Util;

my ($aggregated_mode, $h2o_keepalive, $starlet_keepalive, $starlet_force_chunked, $unix_socket);

GetOptions(
    "mode=i"                  => sub {
        (undef, my $m) = @_;
        $h2o_keepalive = ($m & 1) != 0;
        $starlet_keepalive = ($m & 2) != 0;
        $starlet_force_chunked = ($m & 4) != 0;
        $unix_socket = ($m & 8) != 0;
    },
    "h2o-keepalive=i"         => \$h2o_keepalive,
    "starlet-keepalive=i"     => \$starlet_keepalive,
    "starlet-force-chunked=i" => \$starlet_force_chunked,
    "unix-socket=i"           => \$unix_socket,
) or exit(1);

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
plan skip_all => 'skipping unix-socket tests, requires Starlet >= 0.25'
    if $unix_socket && `perl -MStarlet -e 'print \$Starlet::VERSION'` < 0.25;

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => (stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt halfdome.jpg);

my $huge_file_size = 50 * 1024 * 1024; # should be larger than the mmap_backend threshold of h2o
my $huge_file = create_data_file($huge_file_size);
my $huge_file_md5 = md5_file($huge_file);

my ($unix_socket_file, $unix_socket_guard) = do {
    (undef, my $fn) = tempfile(UNLINK => 0);
    unlink $fn;
    +(
        $fn,
        Scope::Guard->new(sub {
            unlink $fn;
        }),
    );
} if $unix_socket;

my $upstream = $unix_socket_file ? "[unix:$unix_socket_file]" : "127.0.0.1:@{[empty_port()]}";

my $guard = do {
    local $ENV{FORCE_CHUNKED} = $starlet_force_chunked;
    my @args = (qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $unix_socket_file || $upstream);
    if ($starlet_keepalive) {
        push @args, "--max-keepalive-reqs=100";
    }
    push @args, ASSETS_DIR . "/upstream.psgi";
    spawn_server(
        argv     => \@args,
        is_ready =>  sub {
            if ($unix_socket_file) {
                !! -e $unix_socket_file;
            } else {
                $upstream =~ /:([0-9]+)$/s
                    or die "failed to extract port number";
                check_port($1);
            }
        },
    );
};

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://$upstream
      /gzip:
        proxy.reverse.url: http://$upstream
        gzip: ON
      /files:
        file.dir: @{[ DOC_ROOT ]}
@{[ $h2o_keepalive ? "" : "        proxy.timeout.keepalive: 0" ]}
reproxy: ON
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    for my $file (sort keys %files) {
        my $content = `$curl --silent --show-error $proto://127.0.0.1:$port/$file`;
        is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
        is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
    }
    for my $file (sort keys %files) {
        my $content = `$curl --silent --show-error --data-binary \@@{[ DOC_ROOT ]}/$file $proto://127.0.0.1:$port/echo`;
        is length($content), $files{$file}->{size}, "$proto://127.0.0.1/echo (POST, $file, size)";
        is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/echo (POST, $file, md5)";
    }
    if ($curl !~ /--http2/) {
        for my $file (sort keys %files) {
            my $content = `$curl --silent --show-error --header 'Transfer-Encoding: chunked' --data-binary \@@{[ DOC_ROOT ]}/$file $proto://127.0.0.1:$port/echo`;
            is length($content), $files{$file}->{size}, "$proto://127.0.0.1/echo (POST, chunked, $file, size)";
            is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/echo (POST, chunked, $file, md5)";
        }
    }
    my $content = `$curl --silent --show-error --data-binary \@$huge_file $proto://127.0.0.1:$port/echo`;
    is length($content), $huge_file_size, "$proto://127.0.0.1/echo (POST, mmap-backed, size)";
    is md5_hex($content), $huge_file_md5, "$proto://127.0.0.1/echo (POST, mmap-backed, md5)";
    if ($curl !~ /--http2/) {
        $content = `$curl --silent --show-error --header 'Transfer-Encoding: chunked' --data-binary \@$huge_file $proto://127.0.0.1:$port/echo`;
        is length($content), $huge_file_size, "$proto://127.0.0.1/echo (POST, chunked, mmap-backed, size)";
        is md5_hex($content), $huge_file_md5, "$proto://127.0.0.1/echo (POST, chunked, mmap-backed, md5)";
    }
    subtest 'rewrite-redirect' => sub {
        $content = `$curl --silent --dump-header /dev/stdout --max-redirs 0 "$proto://127.0.0.1:$port/?resp:status=302&resp:location=http://@{[uri_escape($upstream)]}/abc"`;
        like $content, qr{HTTP/[^ ]+ 302\s}m;
        like $content, qr{^location: ?$proto://127.0.0.1:$port/abc\r$}m;
    };
    subtest "x-reproxy-url ($proto)" => sub {
        my $fetch_test = sub {
            my $url_prefix = shift;
            for my $file (sort keys %files) {
                my $content = `$curl --silent --show-error "$proto://127.0.0.1:$port/404?resp:status=200&resp:x-reproxy-url=$url_prefix$file"`;
                is length($content), $files{$file}->{size}, "$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$file (md5)";
            }
        };
        subtest "abs-url" => sub {
            $fetch_test->("http://@{[uri_escape($upstream)]}/");
        };
        subtest "abs-path" => sub {
            $fetch_test->("/");
        };
        subtest "rel-path" => sub {
            $fetch_test->("");
        };
        my $content = `$curl --silent --show-error "$proto://127.0.0.1:$port/streaming-body?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/index.txt"`;
        is $content, "hello\n", "streaming-body";
        $content = `$curl --silent "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=https://default/files/index.txt"`;
        is length($content), $files{"index.txt"}->{size}, "to file handler (size)";
        is md5_hex($content), $files{"index.txt"}->{md5}, "to file handler (md5)";
        $content = `$curl --silent "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/?resp:status=302%26resp:location=index.txt"`;
        is length($content), $files{"index.txt"}->{size}, "reproxy & internal redirect to upstream (size)";
        is md5_hex($content), $files{"index.txt"}->{md5}, "reproxy & internal redirect to upstream (md5)";
        $content = `$curl --silent "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/?resp:status=302%26resp:location=https://default/files/index.txt"`;
        is length($content), $files{"index.txt"}->{size}, "reproxy & internal redirect to file (size)";
        is md5_hex($content), $files{"index.txt"}->{md5}, "reproxy & internal redirect to file (md5)";
        $content = `$curl --silent "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://default/files"`;
        is length($content), $files{"index.txt"}->{size}, "redirect handled internally after delegation (size)";
        is md5_hex($content), $files{"index.txt"}->{md5}, "redirect handled internally after delegation (md5)";
    };
    subtest "x-forwarded ($proto)" => sub {
        my $resp = `$curl --silent $proto://127.0.0.1:$port/echo-headers`;
        like $resp, qr/^x-forwarded-for: ?127\.0\.0\.1$/mi, "x-forwarded-for";
        like $resp, qr/^x-forwarded-proto: ?$proto$/mi, "x-forwarded-proto";
        like $resp, qr/^via: ?[^ ]+ 127\.0\.0\.1:$port$/mi, "via";
        $resp = `$curl --silent --header 'X-Forwarded-For: 127.0.0.2' --header 'Via: 2 example.com' $proto://127.0.0.1:$port/echo-headers`;
        like $resp, qr/^x-forwarded-for: ?127\.0\.0\.2, 127\.0\.0\.1$/mi, "x-forwarded-for (append)";
        like $resp, qr/^via: ?2 example.com, [^ ]+ 127\.0\.0\.1:$port$/mi, "via (append)";
    };
    subtest 'issues/266' => sub {
        my $resp = `$curl --dump-header /dev/stderr --silent -H 'cookie: a=@{['x' x 4000]}' $proto://127.0.0.1:$port/index.txt 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 200\s}m;
    };
    subtest 'gzip' => sub {
        plan skip_all => 'curl issue #661'
            if $curl =~ /--http2/;
        my $resp = `$curl --silent -H Accept-Encoding:gzip $proto://127.0.0.1:$port/gzip/alice.txt | gzip -cd`;
        is md5_hex($resp), md5_file("@{[DOC_ROOT]}/alice.txt");
    };
});

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
        my $out = `nghttp $opt -d t/50reverse-proxy/hello.txt $proto://127.0.0.1:$port/echo`;
        is $out, "hello\n", "$proto://127.0.0.1/echo (POST)";
        $out = `nghttp $opt -m 10 $proto://127.0.0.1:$port/index.txt`;
        is $out, "hello\n" x 10, "$proto://127.0.0.1/index.txt x 10 times";
        $out = `nghttp $opt -d $huge_file $proto://127.0.0.1:$port/echo`;
        is length($out), $huge_file_size, "$proto://127.0.0.1/echo (mmap-backed, size)";
        is md5_hex($out), $huge_file_md5, "$proto://127.0.0.1/echo (mmap-backed, md5)";
        subtest 'cookies' => sub {
            plan skip_all => 'nghttp issues #161'
                if $opt eq '-u';
            $out = `nghttp $opt -H 'cookie: a=b' -H 'cookie: c=d' $proto://127.0.0.1:$port/echo-headers`;
            like $out, qr{^cookie: a=b; c=d$}m;
        };
        subtest "x-reproxy-url ($proto)" => sub {
            for my $file (sort keys %files) {
                my $content = `nghttp $opt "$proto://127.0.0.1:$port/404?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/$file"`;
                is length($content), $files{$file}->{size}, "$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$file (md5)";
            }
            my $content = `nghttp $opt "$proto://127.0.0.1:$port/streaming-body?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/index.txt"`;
            is $content, "hello\n", "streaming-body";
            $content = `nghttp $opt "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=https://default/files/index.txt"`;
            is length($content), $files{"index.txt"}->{size}, "to file handler (size)";
            is md5_hex($content), $files{"index.txt"}->{md5}, "to file handler (md5)";
            $content = `nghttp $opt "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/?resp:status=302%26resp:location=index.txt"`;
            is length($content), $files{"index.txt"}->{size}, "reproxy & internal redirect to upstream (size)";
            is md5_hex($content), $files{"index.txt"}->{md5}, "reproxy & internal redirect to upstream (md5)";
            $content = `nghttp $opt "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://@{[uri_escape($upstream)]}/?resp:status=302%26resp:location=https://default/files/index.txt"`;
            is length($content), $files{"index.txt"}->{size}, "reproxy & internal redirect to file (size)";
            is md5_hex($content), $files{"index.txt"}->{md5}, "reproxy & internal redirect to file (md5)";
            $content = `nghttp -v $opt "$proto://127.0.0.1:$port/?resp:status=200&resp:x-reproxy-url=http://default/files"`;
            unlike $content, qr/ :status: 3/, "once delegated, redirects of the file handler should be handled internally";
        };
        subtest 'issues/185' => sub {
            my $out = `nghttp $opt -v "$proto://127.0.0.1:$port/?resp:access-control-allow-origin=%2a"`;
            is $?, 0;
            like $out, qr/ access-control-allow-origin: \*$/m;
        };
        subtest 'issues/192' => sub {
            my $cookie = '_yohoushi_session=ZU5tK2FhcllVQ1RGaTZmZE9MUXozZnAzdTdmR250ZjRFU1hNSnZ4Y2JxZm9pYzJJSEpISGFKNmtWcW1HcjBySmUxZzIwNngrdlVIOC9jdmg0R3I3TFR4eVYzaHlFSHdEL1M4dnh1SmRCbVl3ZE5FckZEU1NyRmZveWZwTmVjcVV5V1JhNUd5REIvWjAwQ3RiT1ZBNGVMUkhiN0tWR0c1RzZkSVhrVkdoeW1lWXRDeHJPUW52NUwxSytRTEQrWXdoZ1EvVG9kak9aeUxnUFRNTDB4Vis1RDNUYWVHZm12bDgwL1lTa09MTlJYcGpXN2VUWmdHQ2FuMnVEVDd4c3l1TTJPMXF1dGhYcGRHS2U2bW9UaG0yZGIwQ0ZWVzFsY1hNTkY5cVFvWjNqSWNrQ0pOY1gvMys4UmRHdXJLU1A0ZTZQc3pSK1dKcXlpTEF2djJHLzUwbytwSnVpS0xhdFp6NU9kTDhtcmgxamVXMkI0Nm9Nck1rMStLUmV0TEdUeGFSTjlKSzM0STc3NTlSZ05ZVjJhWUNibkdzY1I1NUg4bG96dWZSeGorYzF4M2tzMGhKSkxmeFBTNkpZS09HTFgrREN4SWd4a29kamRxT3FobDRQZ2xMVUE9PS0tQUxSWU5nWmVTVzRoN09sS3pmUVM3dz09--3a411c0cf59845f0b8ccf61f69b8eb87aa1727ac; path=/; HttpOnly';
            my $cookie_encoded = $cookie;
            $cookie_encoded =~ s{([^A-Za-z0-9_])}{sprintf "%%%02x", ord $1}eg;
            $out = `nghttp $opt -v $proto://127.0.0.1:$port/?resp:set-cookie=$cookie_encoded`;
            is $?, 0;
            like $out, qr/ set-cookie: $cookie$/m;
        };
    };
    subtest 'http (upgrade)' => sub {
        $doit->('http', '-u', $server->{port});
    };
    subtest 'http (direct)' => sub {
        $doit->('http', '', $server->{port});
    };
    subtest 'https' => sub {
        plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
            unless openssl_can_negotiate();
        $doit->('https', '', $server->{tls_port});
    };
};

done_testing;
