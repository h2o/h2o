use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $upstream_hostport = "127.0.0.1:$upstream_port";

sub create_upstream {
    my @args = (
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen),
        $upstream_hostport,
        ASSETS_DIR . "/upstream.psgi",
    );
    spawn_server(
        argv     => \@args,
        is_ready =>  sub {
            $upstream_hostport =~ /:([0-9]+)$/s
                or die "failed to extract port number";
            check_port($1);
        },
    );
};

sub doit {
    my $timeout = shift;
    my $server = spawn_h2o(<< "EOT");
http2-graceful-shutdown-timeout: $timeout
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

    my $upstream = create_upstream();
    my $nghttp_pid = open(NGHTTP, "nghttp -w 1 -v http://127.0.0.1:$server->{'port'}/infinite-stream 2>&1 |");

    my $nghttp_interrupted=0;
    eval {
        local $SIG{ALRM} = sub { die "Timeout" };
        my $stopped=0;
        alarm(5);
        while (<NGHTTP>) {
            if (/recv DATA frame/ && !$stopped) {
                # after the request started, stop H2O
                kill 'TERM', $server->{pid};
                $stopped = 1;
            }
            if (/Some requests were not processed/) {
                $nghttp_interrupted = 1;
            }
        }
        alarm(0);
    };
    my $err = $@;
    if ($timeout == 1) {
        ok($nghttp_interrupted == 1, "nghttp was interrupted");
        ok($err !~ /^Timeout/, "nghttp didn't timeout");
    } else {
        kill 'TERM', $nghttp_pid;
        ok($nghttp_interrupted == 0, "nghttp was not interrupted");
        ok($err =~ /^Timeout/, "nghttp did timeout");
    }
}

doit(0);
doit(1);

done_testing();
