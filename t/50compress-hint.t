use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nc not found'
    unless prog_exists('nc');

plan skip_all => 'curl not found'
    unless prog_exists('curl');

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
compress: ON
compress-minimum-size: 10
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub doit {
    my $msg = shift;
    my $x_compress_header = shift;
    my $expect_content_encoding = shift;
    my $accept_gzip = shift;

    my $ae_header = "";
    if ($accept_gzip) {
        $ae_header = "-Haccept-encoding:gzip";
    }
    open(CURL, "curl $ae_header -Hhost:host.example.com -svo /dev/null http://127.0.0.1:$server->{'port'}/ 2>&1 |");

    my $req;
    $client_socket = $socket->accept();
    $client_socket->recv($req, 1024);
    my $cl = length($msg);
    $client_socket->send("HTTP/1.1 200 Ok\r\ncontent-length:${cl}\r\ncontent-type:text/html\r\n${x_compress_header}Connection:close\r\n\r\n$msg");
    close($client_socket);

    my $seen_content_encoding = 0;
    while(<CURL>) {
        if (/< content-encoding/) {
            $seen_content_encoding = 1;
        }
    }

    my $neg = "";
    if ($expect_content_encoding == 0) {
        $neg = "not ";
    }
    ok($seen_content_encoding == $expect_content_encoding, "The body was ${neg}encoded as expected");
}

doit("This is large enough to be compressed", "", 1, 1);
doit("This is large enough to be compressed", "x-compress-hint: auto\r\n", 1, 1);
doit("This is large enough to be compressed", "x-compress-hint: on\r\n", 1, 1);
doit("This is large enough to be compressed", "x-compress-hint: off\r\n", 0, 1);

doit("too small", "", 0, 1);
doit("too small", "x-compress-hint: auto\r\n", 0, 1);
doit("too small", "x-compress-hint: on\r\n", 1, 1);
doit("too small", "x-compress-hint: off\r\n", 0, 1);

doit("This is large enough to be compressed", "", 0, 0);
doit("This is large enough to be compressed", "x-compress-hint: auto\r\n", 0, 0);
doit("This is large enough to be compressed", "x-compress-hint: on\r\n", 0, 0);
doit("This is large enough to be compressed", "x-compress-hint: off\r\n", 0, 0);

$socket->close();
done_testing();
