use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(time);
use IO::Socket::INET;
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

sub create_upstream {
# creating a listening socket
    my $socket = new IO::Socket::INET (
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1
    );
    die "cannot create socket $!\n" unless $socket;
    return $socket;
};

sub handler_curl {
    my $socket = shift;
    my $client_socket = $socket->accept();

    my $data = "";
    print($client_socket->recv($data, 4096));

    my $header = "HTTP/1.0 200 Ok\r\nConnection: close\r\n\r\n";
    $client_socket->send($header);
    my $start = time();
    for (1..200) {
        $client_socket->send("abcabcabc\n" x 100000) == 1000000
             or die "failed to write to socket:$!";
    }
    my $duration = time() - $start;
    $client_socket->send("\n$duration");

    close($client_socket)
        or die "close failed:$!";
};

my $upstream = create_upstream();

sub max_buffer_size_test {

    my $max_on = shift;
    my $directive = "";

    if ($max_on == 1) {
        $directive = "proxy.max-buffer-size: 1000";
    }
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        $directive
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $start = time();
        open(CURL, "$curl --limit-rate 40M -s $proto://127.0.0.1:$port/ 2>&1 | tail -n 1 |");
        handler_curl($upstream);
        my $resp = <CURL>;
        my $duration = time() - $start;
        # handle_curl() writes 200M and curl downloads at 40M/s, so it
        # should take about 5 seconds to download
        # when the proxy.max-buffer-size is not set, H2O will buffer the
        # whole 200M, so the time spent in handler_curl() will be very small.
        # OTOH, when the setting is set, it will take about the same time
        # to write to H2O, as it will take for curl download  the response
        if ($max_on) {
            cmp_ok($duration - $resp, '<=', 2, "Writing to H2O was as fast as the curl download");
        } else {
            cmp_ok($duration - $resp, '>', 3, "Writing to H2O was much faster than the curl download");
        }
    });
}

subtest "no max buffer size" => sub {
    max_buffer_size_test(0);
};
subtest "max buffer size" => sub {
    max_buffer_size_test(1);
};

done_testing();
