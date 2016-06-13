use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

subtest "tcp" => sub {
    my $port = empty_port();
    my $upstream = spawn_upstream($port);
    doit("127.0.0.1:$port", 1);
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
    doit("[unix:$sockfn]", 0);
};

done_testing;

sub doit {
    my $upaddr = shift;
    my $tcp = shift;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://$upaddr
        proxy.timeout.io: 1000
        proxy.timeout.keepalive: 10000
        proxy.per_client_socket_pool: ON
EOT
    my $port = $server->{port};

    sub issue_req {
        sub uniq {
            my %seen;
            return grep { !$seen{$_}++ } @_;
        }
        my $port = shift;
        my ($ignore, $resp) = run_prog("nghttp -v -a -n http://127.0.0.1:$port/echo-port");
        my @ports = map { /x-remote-port: (\d+)$/; $1; } grep(/x-remote-port/, split(/\n/, $resp));
        is @ports, 2, "Found two requests as expected";
        my @unic = uniq(@ports);
        is @unic, 1, "All ports used by h2o are the same";
        return $unic[0];
    };
    my $first_port = issue_req($port);
    if (!$tcp) {
        # return early if it's not tcp: we can't really verify
        # that we're re-using the same port. Let's just very that the
        # query works as expected.
        return;
    }
    my $second_port = issue_req($port);

    sleep 2;
    my $third_port = issue_req($port);
    sleep 2;
    my $fourth_port = issue_req($port);
    my $fifth_port = issue_req($port);

    isnt $first_port, $second_port, "first and second frontend connections used a different backend connection";
    isnt $second_port, $third_port, "second and third frontend connections used a different backend connection";
    isnt $third_port, $fourth_port, "third and fourth frontend connections used a different backend connection";
    isnt $fourth_port, $fifth_port, "fourth and fifth frontend connections used a different backend connection";
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
