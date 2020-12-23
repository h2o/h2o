use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use URI::Escape;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $h3client = bindir() . "/h2o-httpclient";

subtest 'forward' => sub {
    subtest '100 Continue' => sub {
        do_forward(100);
    };
    subtest '103 Early Hints' => sub {
        do_forward(103);
    };
};

subtest 'send 103' => sub {
    my $server = spawn_h2o(<< "EOT");
send-informational: all
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      stash: &header
        header.add:
          header:
            - "foo: FOO"
          when: early
      /async:
        <<: *header
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /sync:
        <<: *header
        file.dir: @{[DOC_ROOT]}
EOT
    subtest 'async' => sub {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp;
            $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/async'`;
            like $resp, qr{^HTTP/[\d.]+ 103}mi;
            (my $eh, $resp) = split(/\r\n\r\n/, $resp, 2);
            like $eh, qr{^foo: FOO}mi;
        });
        subtest 'http/3' => sub {
            plan skip_all => "$h3client not found"
                unless -e $h3client;
            my $resp = `$h3client -3 100 https://127.0.0.1:$quic_port/async/index.txt 2>&1`;
            like $resp, qr{^HTTP/3 103\n.*?foo: FOO.*\n\nHTTP/3 200\n}s;
        };
    };
    subtest 'sync' => sub {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp;
            $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/sync'`;
            unlike $resp, qr{^HTTP/[\d.]+ 103}mi;
        });
        subtest 'http/3' => sub {
            plan skip_all => "$h3client not found"
                unless -e $h3client;
            my $resp = `$h3client -3 100 https://127.0.0.1:$quic_port/sync/index.txt 2>&1`;
            like $resp, qr{^HTTP/3 200\n}s;
        };
    };
};

subtest 'broken memory issue when keepalive is used' => sub {
    my $server = spawn_h2o(<< "EOT");
send-informational: all
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my $resp;
    my $url = "http://127.0.0.1:$server->{port}/early-hints";
    $resp = `curl --http1.1 --silent --dump-header /dev/stdout '$url' '$url?sleep'`;
    my @m = $resp =~ m{HTTP/1.1 200 OK}g;
    is(scalar(@m), 2) or diag $resp;
};

done_testing();

sub do_forward {
    my ($status) = @_;
    my $link = $status == 103 ? 1 : 0;

    subtest 'all' => sub {
        my $server = spawn_h2o(<< "EOT");
send-informational: all
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /tweak-headers:
        header.unset:
          header: "link"
          when: early
        header.add:
          header:
            - "foo: FOO"
            - "bar: BAR"
          when: early
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp;
            $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/1xx?status=$status&link=$link'`;
            like $resp, qr{^HTTP/[\d.]+ $status}mi;
            (my $eh, $resp) = split(/\r\n\r\n/, $resp, 2);
            like $eh, qr{^link: </index.js>; rel=preload}mi if $link;
    
            subtest '103 with no hints' => sub {
                $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/1xx?status=$status'`;
                unlike $resp, qr{^HTTP/[\d.]+ $status}mi;
            } if $status == 103;

            subtest 'tweak headers' => sub {
                $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/tweak-headers/1xx?status=$status&link=1'`;
                my ($early, $info, $resp) = split("\r\n\r\n", $resp, 3);
                like $early, qr{^foo: FOO}mi;
                like $early, qr{^bar: BAR}mi;
                like $info, qr{^HTTP/[\d.]+ $status}mi;
                if ($status == 103) {
                    like $info, qr{^foo: FOO}mi;
                    like $info, qr{^bar: BAR}mi;
                    unlike $info, qr{^link: }mi;
                } else {
                    unlike $info, qr{^foo: FOO}mi;
                    unlike $info, qr{^bar: BAR}mi;
                    like $info, qr{^link: }mi;
                }
            };
        });
    };
    
    subtest 'except-h1 (default)' => sub {
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/1xx?status=$status&link=$link'`;
            if ($curl =~ /http2/) {
                like $resp, qr{^HTTP/[\d.]+ $status}mi;
            } else {
                unlike $resp, qr{^HTTP/[\d.]+ $status}mi;
            }
        });
    };
    
    subtest 'none' => sub {
        my $server = spawn_h2o(<< "EOT");
send-informational: none
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/1xx?status=$status&link=$link'`;
            unlike $resp, qr{^HTTP/[\d.]+ $status}mi;
        });
    };
}
