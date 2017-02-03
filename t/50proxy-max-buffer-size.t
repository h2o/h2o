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

plan skip_all => 'curl not found'
    unless prog_exists('curl');

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

my $upstream = create_upstream();

sub max_buffer_size_test {

    my $max_on = shift;
    my $directive = "";

    if ($max_on == 1) {
        $directive = "proxy.max-buffer-size: 10000";
    }
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        $directive
EOT

    #

    my $nghttp_pid = open(NGHTTP, "nghttp -t 10 -nv 'http://127.0.0.1:$server->{'port'}/big-stream?size=30000000' 2>&1 |");

    sleep(1);
    kill 'STOP', $nghttp_pid;
    my $n=0;
    my $saw_tmp_file = 0;
    while ($n < 100) {
        $n++;
        chomp(my $nr_tmp_file = `lsof -np $server->{'pid'} 2> /dev/null | grep '/tmp/h2o.' | grep deleted | wc -l`);
        if ($nr_tmp_file > 0) {
            $saw_tmp_file = 1;
            last;
        }
        sleep .1;
    }
    if ($max_on) {
        ok($saw_tmp_file == 0, "Didn't see a temporary file");
    } else {
        ok($saw_tmp_file == 1, "Saw a temporary file");
    }

    chomp(my $estab = `lsof -np $server->{'pid'} 2> /dev/null | grep ESTABLISHED | grep $upstream_port | wc -l`);
    if ($max_on == 1) {
        ok($estab ==  1, "Connection to upstream was not closed");
    } else {
        ok($estab ==  0, "Connection to upstream has been closed");
    }
    kill 'CONT', $nghttp_pid;

    my $saw_end = 0;
    while (<NGHTTP>) {
        if (/NO_ERROR/) {
            $saw_end = 1;
            close(NGHTTP);
            last;
        }
    }

    ok($saw_end == 1, "Stream finished as expected");
}

max_buffer_size_test(0);
max_buffer_size_test(1);

done_testing();
