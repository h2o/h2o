use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

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

my $msg = "this is the message";
open(NGHTTP, "nghttp -t 3 -w 1 -v http://127.0.0.1:$server->{'port'}/ -H 'host: host.example.com' 2>&1 |");

my $req;
$client_socket = $socket->accept();
$client_socket->recv($req, 1024);
$client_socket->send("HTTP/1.1 200 Ok\r\nConnection:close\r\n\r\n$msg");
close($client_socket);

my $worked = 1;
while(<NGHTTP>) {
    if (/Timeout/) {
        $worked = 0;
    }
}

ok($worked == 1, "The connection didn't timeout");

$socket->close();
done_testing();
