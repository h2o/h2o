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

subtest '100 Continue' => sub {
    doit(100);
};
subtest '103 Early Hints' => sub {
    doit(103);
};
done_testing();

sub doit {
    my ($status) = @_;
    my $link = $status == 103 ? 1 : 0;

    subtest 'all' => sub {
        my $server = spawn_h2o(<< "EOT");
forward-informational: all
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
    
            if ($status == 103) {
                $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/1xx?status=$status'`;
                unlike $resp, qr{^HTTP/[\d.]+ $status}mi, 'no hints received';

                $resp = `$curl --silent --dump-header /dev/stdout '$proto://127.0.0.1:$port/tweak-headers/1xx?status=$status'`;
                (my $early, $resp) = split("\r\n\r\n", $resp, 2);
                like $early, qr{^HTTP/[\d.]+ $status}mi;
                like $early, qr{^foo: FOO}mi;
                like $early, qr{^bar: BAR}mi;
                unlike $early, qr{^link: }mi;
            }
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
forward-informational: none
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
