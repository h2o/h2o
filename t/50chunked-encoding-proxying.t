use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use Time::HiRes qw(usleep);

plan skip_all => 'nc not found'
    unless prog_exists('nc');

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $upstream_port = empty_port();
$| = 1;
my $socket = new IO::Socket::INET (
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
);
die "cannot create socket $!\n" unless $socket;

check_port($upstream_port) or die "can't connect to server socket";
# accent and close check_port's connection
my $client_socket = $socket->accept();
close($client_socket);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub doit {
    my $chunk = shift;
    my $data = shift;
    my $stream_window_bits = shift;
    my $defer_close = shift;
    my $expect_rst_stream = shift;
    open my $nghttp, "-|", "nghttp -w $stream_window_bits -v http://127.0.0.1:$server->{'port'}/ -H 'host: host.example.com' 2>&1";

    my $req;
    $client_socket = $socket->accept();
    $client_socket->recv($req, 1024);
    $client_socket->send("HTTP/1.1 200 Ok\r\nTransfer-Encoding:chunked\r\nConnection:close\r\n\r\n$chunk");
    if ($defer_close) {
        usleep(50000);
    }
    close($client_socket);

    my $found_rst_stream=0;
    my $found_data="";
    while(<$nghttp>) {
        if (/^[\[|\s]/) {
            if (/RST_STREAM/) {
                $found_rst_stream = 1;
            }
        } else {
            # reassamble the DATA output
            if (/^([^\[|^\s]+)[\[|\s].*DATA.*/) {
                $found_data = $found_data.$1;
            }
        }
    }
    if ($expect_rst_stream) {
        ok($found_rst_stream == 1, "Found RST_STREAM");
    } else {
        ok($found_rst_stream == 0, "RST_STREAM not found, as expected");
    }
    ok($found_data eq $data, "Found the expected data");
}

for my $w (1 .. 5) {
    doit("5\r\nHello\r\n50\r\nThere", "HelloThere", $w, 0, 1);
    doit("5\r\nHello\r\n50\r\nThere", "HelloThere", $w, 1, 1);
}
doit("5\r\nHello\r\n5\r\nThere\r\n", "HelloThere", 14);

$socket->close();
done_testing();
