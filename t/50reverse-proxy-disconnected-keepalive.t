use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

subtest "tcp" => sub {
    my $port = empty_port();
    my $upstream = spawn_upstream($port);
    doit("127.0.0.1:$port");
};

subtest "unix-socket" => sub {
    plan skip_all => 'skipping unix-socket tests, requires Starlet >= 0.25'
        if `perl -MStarlet -e 'print \$Starlet::VERSION'` < 0.25;

    (undef, my $sockfn) = tempfile(UNLINK => 0);
    unlink $sockfn;
    my $guard = Scope::Guard->new(sub {
        unlink $sockfn;
    });

    my $upstream = spawn_upstream($sockfn);
    doit("[unix:$sockfn]");
};

done_testing;

sub doit {
    my $upaddr = shift;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://$upaddr
        proxy.timeout.io: 1000
        proxy.timeout.keepalive: 10000
EOT
    my $port = $server->{port};

    my $check_req = sub {
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$port/index.txt 2>&1");
        like $headers, qr{^HTTP/1\.1 200 }is;
        is $body, "hello\n";
    };
    subtest "first-connect"  => $check_req;
    subtest "redo-immediate" => $check_req;
    sleep 2;
    subtest "redo-after-upstream-disconnect" => $check_req;
    sleep 2;
    subtest "once-more" => $check_req;
};

sub spawn_upstream {
    my $addr = shift;
    spawn_server(
        argv     => [
            qw(plackup -s Starlet --max-keepalive-reqs 100 --keepalive-timeout 1 --access-log /dev/null --listen), $addr,
            ASSETS_DIR . "/upstream.psgi"
        ],
        is_ready => sub {
            if ($addr =~ /^\d+$/) {
                check_port($addr);
            } else {
                !! -e $addr;
            }
        },
    );
}
