use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

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
) or die "cannot create socket $!\n";

check_port($upstream_port) or die "can't connect to server socket";
# accent and close check_port's connection
my $client_socket = $socket->accept();
close($client_socket);

my $server = spawn_h2o(<< "EOT");
compress: ON
compress-minimum-size: 1
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub doit {
    my $msg = shift;
    my $x_compress_header = shift;
    my $resp_content_encoding = shift;
    my $etag = shift;
    my $expect_etag = shift;

    my $ce_header = "";
    if ($resp_content_encoding ne "") {
        $ce_header = "content-encoding:$resp_content_encoding\r\n";
    }
    open(
        my $curl,
        "-|",
        "curl -Haccept-encoding:br,gzip -Hhost:host.example.com -svo /dev/null http://127.0.0.1:$server->{'port'}/ 2>&1",
    ) or die "failed to launch curl:$!";

    my $req;
    $client_socket = $socket->accept();
    $client_socket->recv($req, 1024);
    my $cl = length($msg);
    $client_socket->send("HTTP/1.1 200 Ok\r\ncontent-length:${cl}\r\n${ce_header}etag:${etag}\r\n${x_compress_header}connection:close\r\n\r\n$msg");
    close($client_socket);

    my $seen_etag = "";
    while(<$curl>) {
        if (/< etag: (.*)\r\n/) {
            $seen_etag = $1;
        }
    }

    ok($seen_etag eq $expect_etag, "The seen etag header (".$seen_etag.") was the one expected (".$expect_etag.")");
}


doit("The compressed response", "x-compress-hint: on\r\n", "", "theetag", "W/theetag");
doit("The compressed response", "x-compress-hint: on\r\n", "", "W/theetag", "W/theetag");
doit("The compressed response", "x-compress-hint: on\r\n", "gzip", "theetag", "theetag");
doit("The compressed response", "x-compress-hint: on\r\n", "gzip", "W/theetag", "W/theetag");



$socket->close();
done_testing();
