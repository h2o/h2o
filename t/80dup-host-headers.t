use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $upstream_port = empty_port();
$| = 1;
my $socket = new IO::Socket::INET (
    LocalHost => '0.0.0.0',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
);
die "cannot create socket $!\n" unless $socket;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

system("nghttp http://127.0.0.1:$server->{'port'}/ -H 'host: host.example.com' &");

my $client_socket = $socket->accept();
$client_socket->recv(my $req, 1024);
$client_socket->send("HTTP/1.1 200 Ok\r\nConnection:close\r\n\r\nBody\r\n");
close($client_socket);
$socket->close();

my $host_headers = 0;
foreach (split(/\r\n/, $req)) {
    if (/^host:/i) {
        $host_headers++
    }
}

is $host_headers, 1, "Only saw one host: header";
done_testing();
