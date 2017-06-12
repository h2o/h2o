use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

sub create_upstream {
    my $upstream_port = shift;
    spawn_server(
        argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub {
            if ($upstream_port =~ /^\//) {
                !! -e $upstream_port;
            } else {
                check_port($upstream_port);
            }
        },
    );
}

my $upstream_port1 = empty_port();
my $upstream_port2 = empty_port();
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
my $up1 = create_upstream($upstream_port1);
my $up2 = create_upstream($upstream_port2);
my $up3 = create_upstream($unix_socket_file);

my $server = spawn_h2o(<< "EOT");
backend:
    id: a
    url: http://127.0.0.1:$upstream_port1
backend:
    id: b
    url: http://127.0.0.1.xip.io:$upstream_port2
backend:
    id: c
    url: http://[unix:$unix_socket_file]
hosts:
    default:
        paths:
            /:
                proxy.reverse.url:
                    header: backend-id
EOT

run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl -Hbackend-id:a --silent $proto://127.0.0.1:$port/echo-headers`;
        like $resp, qr{^host:.*:(\d+)}m, "Found port in hostname";
        $resp =~ qr{^host:.*:(\d+)}m;
        ok $1 == $upstream_port1, "ok $1";

        $resp = `$curl -Hbackend-id:b --silent $proto://127.0.0.1:$port/echo-headers`;
        like $resp, qr{^host:.*:(\d+)}m, "Found port in hostname";
        $resp =~ qr{^host:.*:(\d+)}m;
        ok $1 == $upstream_port2, "ok $1";

        $resp = `$curl -Hbackend-id:c --silent $proto://127.0.0.1:$port/echo-headers`;
        like $resp, qr{^host:.*unix:(\S+)\]}m, "Found unix path";
        $resp =~ qr{^host:.*unix:(\S+)\]}m;
        ok $1 eq $unix_socket_file, "ok $1";
    }
);

done_testing();
