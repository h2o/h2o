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

sub doone {
    my $cmd = shift;
    my $upstream_response = shift;
    my $expected = shift;
    my $test_description = shift;
    die unless pipe(my $reader, my $writer);
    my $pid = fork();
    die if not defined $pid;
    if ($pid == 0) {
        $| = 1;
        close($reader);
        print $writer qx{$cmd};
        close($writer);
        exit(0);
    }

    close($writer);

    my $req;
    $client_socket = $socket->accept();
    $client_socket->recv($req, 1024);
    $client_socket->send($upstream_response);
    close($client_socket);
    my $curl_output = do { local $/; <$reader> };
    like $curl_output, qr{$expected}, $test_description; 
    close($reader);
    wait();
}

sub doit {
    my $proto = shift;
    my $cmd = "curl -k -svo /dev/null --http${proto} https://127.0.0.1:$server->{'tls_port'}/ 2>&1";
    my $resp_preface = "HTTP/1.1 200 Ok\r\nTransfer-encoding:chunked\r\n\r\n";
    my $err_string = "Illegal or missing hexadecimal sequence in chunked-encoding";
    if ($proto == "2") {
        $err_string = "was not closed cleanly";
    }

    doone($cmd, $resp_preface."1\r\na", "left intact", "HTTP/$proto curl reports a clean connection on missing \\r\\n0\\r\\n");

    doone($cmd, $resp_preface, $err_string, "HTTP/$proto curl reports a broken connection when upstream sent no chunks");

    doone($cmd, $resp_preface."2\r\na", $err_string, "HTTP/$proto curl reports a broken connection on truncated chunk");

    doone($cmd, $resp_preface."1", $err_string, "HTTP/$proto curl reports a broken connection on truncated chunk size");
}

subtest "HTTP/1.1" => sub {
    doit("1.1");
};

subtest "HTTP/2" => sub {
    doit("2");
};

$socket->close();
done_testing();
