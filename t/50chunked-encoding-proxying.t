use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nc not found'
    unless prog_exists('nc');

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

open(NGHTTP, "nghttp -v http://127.0.0.1:$server->{'port'}/ -H 'host: host.example.com' 2>&1 |");

my $req;
$client_socket = $socket->accept();
$client_socket->recv($req, 1024);
$client_socket->send("HTTP/1.1 200 Ok\r\nTransfer-Encoding:chunked\r\nConnection:close\r\n\r\n5\r\nHello\r\n5\r\nThere\r\n");
close($client_socket);
$socket->close();

my $found_rst_stream=0;
while(<NGHTTP>) {
    if (/RST_STREAM/) {
        $found_rst_stream = 1;
    }
}
ok($found_rst_stream == 1, "Found RST_STREAM");

done_testing();
