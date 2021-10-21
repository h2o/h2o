use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $upstream_port = empty_port();
my $upstream = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
) or die "cannot create socket: $!";

sub do_upstream {
    my $client = $upstream->accept;
    while (my $buf = <$client>) { last if $buf eq "\r\n" }
    $client->send("HTTP/1.1 200 OK\r\nfoo: FOO\r\n    hoge\r\nConnection: close\r\n\r\n");
    $client->flush;
    close($client);
}

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

open(CURL, "curl --http1.1 --silent --dump-header /dev/stdout 'http://127.0.0.1:$server->{port}/' |");
do_upstream();
my $resp = join('', <CURL>);

like $resp, qr{^HTTP/1\.1 502 .*Content-Length:\s*46.*\r\n\r\nline folding of header fields is not supported$}is;

done_testing();
