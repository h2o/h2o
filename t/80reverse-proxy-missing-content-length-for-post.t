use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'curl does not support HTTP/2'
    unless curl_supports_http2();

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
# accept and close check_port's connection
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
    my $cmd = shift;
    my $should_see_cl = shift;
    my $cl_value = shift;
    system($cmd);

    my $req;
    $client_socket = $socket->accept();
    $client_socket->recv($req, 1 * 1024);
    $client_socket->send("HTTP/1.1 200 Ok\r\nConnection:close\r\n\r\nBody\r\n");
    close($client_socket);

    my $cl_actual_value = -1;
    my $cl_headers = 0;
    foreach (split(/\r\n/, $req)) {
        if (/^content-length:(.*)$/i) {
            $cl_headers++;
            $cl_actual_value = $1;
        }
    }
    if ($should_see_cl) {
        ok($cl_headers == 1, "Saw one, and only one content-length: header");
        ok($cl_actual_value == $cl_value, "content-length: header has the expected value");
    } else {
        ok($cl_headers == 0, "Saw no content-length: header");
    }
}
my $file_size = 512;
my $file = create_data_file($file_size);

# curl doesn't add a CL header when using -X POST
doit("curl -so /dev/null --http2 -X POST http://127.0.0.1:$server->{'port'}/ &", 1, 0);
# curl adds a content-length:0 header when using --data ''
doit("curl -so /dev/null --http2 --data '' http://127.0.0.1:$server->{'port'}/ &", 1, 0);

# check that an existing CL header is preserved
doit("curl -so /dev/null --http2 --data 'a=b' http://127.0.0.1:$server->{'port'}/ &", 1, 3);
doit("curl -so /dev/null --http2 --header 'transfer-encoding: chunked' --data-binary \@$file -X POST http://127.0.0.1:$server->{'port'}/ &", 1, $file_size);

$socket->close();
done_testing();
