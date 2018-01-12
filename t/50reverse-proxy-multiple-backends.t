use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use File::Temp qw(tempdir);

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

sub run_test {
    my ($conf, @candidates) = @_;
    my ($server, $use_keepalive);

    my $regex = join "|", map { quotemeta $_ } @candidates;
    $regex = qr/^($regex)$/
        or die "failed to compile regex";

    my $test = sub {
        for my $i (0..20) {
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($headers, $body) = run_prog("$curl --dump-header /dev/stderr --silent $proto://127.0.0.1:$port/");
                like $headers, qr/^req-connection: @{[$use_keepalive ? "keep-alive" : "close"]}/im
                    unless $curl =~ / --http2( |$)/;
                like $body, $regex;
            });
        }
    };

    subtest "keepalive-on", sub {
        $server = spawn_h2o($conf);
        $use_keepalive = 1;
        $test->();
    };

    subtest "keepalive-off", sub {
        $server = spawn_h2o(<< "EOT");
$conf
proxy.timeout.keepalive: 0
EOT
        $use_keepalive = 0;
        $test->();
    };
}

subtest "both-tcp", sub {
    my $upstream_port1 = empty_port();
    my $upstream_port2 = empty_port();

    my $guard1 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port1, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            check_port($upstream_port1);
        },
    );

    my $guard2 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port2, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            check_port($upstream_port2);
        },
    );

    run_test(<< "EOT", $upstream_port1, $upstream_port2);
hosts:
  default:
    paths:
      /:
        proxy.reverse.url:
          - http://127.0.0.1.xip.io:$upstream_port1/echo-server-port
          - http://127.0.0.1.xip.io:$upstream_port2/echo-server-port
EOT
};

subtest "both-unix", sub {
    my $upstream_file1 = "$tempdir/sock1";
    my $upstream_file2 = "$tempdir/sock2";

    my $guard1 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_file1, ASSETS_DIR . "/upstream.psgi" ],
        is_ready => sub {
            !! -e $upstream_file1;
        },
    );

    my $guard2 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_file2, ASSETS_DIR . "/upstream.psgi" ],
        is_ready => sub {
            !! -e $upstream_file2;
        },
    );

    run_test(<< "EOT", $upstream_file1, $upstream_file2);
hosts:
  default:
    paths:
      /:
        proxy.reverse.url:
          - http://[unix:$upstream_file1]/echo-server-port
          - http://[unix:$upstream_file2]/echo-server-port
EOT
};

subtest "tcp-unix", sub {
    my $upstream_port = empty_port();
    my $upstream_file = "$tempdir/sock3";

    my $guard1 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            check_port($upstream_port);
        },
    );

    my $guard2 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_file, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            !! -e $upstream_file;
        },
    );

    run_test(<< "EOT", $upstream_port, $upstream_file);
hosts:
  default:
    paths:
      /:
        proxy.reverse.url:
          - http://127.0.0.1.xip.io:$upstream_port/echo-server-port
          - http://[unix:$upstream_file]/echo-server-port
EOT
};

done_testing();
