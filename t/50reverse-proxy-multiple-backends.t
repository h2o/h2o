use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use File::Temp qw(tempfile);

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

sub do_test_both_tcp {
    my $balancer = shift;
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

    my $unexpected = 0;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.backends:
          - http://127.0.0.1.XIP.IO:$upstream_port1
          - http://127.0.0.1.XIP.IO:$upstream_port2
        proxy.reverse.path: /echo-server-port
        proxy.reverse.balancer: $balancer
EOT

    for my $i (0..20) {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
            if ($resp ne $upstream_port1 and $resp ne $upstream_port2) {
                $unexpected = 1;
            }
            isnt $unexpected, 1, "both tcp"
        });
    }
}

sub get_unix_socket {
    my ($unix_socket_file, $unix_socket_guard) = do {
        (undef, my $fn) = tempfile(UNLINK => 0);
        unlink $fn;
        +(
            $fn,
            Scope::Guard->new(sub {
                unlink $fn;
                              }),
            );
    };
    return $unix_socket_file
}

sub do_test_both_unix {
    my $balancer = shift;
    my $upstream_file1 = get_unix_socket();
    my $upstream_file2 = get_unix_socket();

    my $guard1 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_file1, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            !! -e $upstream_file1;
        },
        );

    my $guard2 = spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_file2, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            !! -e $upstream_file2;
        },
        );

    my $unexpected = 0;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.backends:
          - http://[unix:$upstream_file1]
          - http://[unix:$upstream_file2]
        proxy.reverse.path: /echo-server-port
        proxy.reverse.balancer: $balancer
EOT

    for my $i (0..20) {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
            if ($resp ne $upstream_file1 and $resp ne $upstream_file2) {
                $unexpected = 1;
            }
            isnt $unexpected, 1, "both unix socket"
        });
    }
}

sub do_test_tcp_unix {
    my $balancer = shift;
    my $upstream_port = empty_port();
    my $upstream_file = get_unix_socket();

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

    my $unexpected = 0;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.backends:
          - http://127.0.0.1.XIP.IO:$upstream_port
          - http://[unix:$upstream_file]
        proxy.reverse.path: /echo-server-port
        proxy.reverse.balancer: $balancer
EOT

    for my $i (0..20) {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
            if ($resp ne $upstream_port and $resp ne $upstream_file) {
                $unexpected = 1;
            }
            isnt $unexpected, 1, "tcp & unix socket"
        });
    }
}

sub do_test {
    my $balancer = shift;
    do_test_both_tcp($balancer);
    do_test_both_unix($balancer);
    do_test_tcp_unix($balancer);
}

do_test("round-robin");
do_test("least-conn");
do_test("hash");
done_testing();
