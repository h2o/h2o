use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();

my $upstream = new IO::Socket::INET (
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
);
die "cannot create socket $!\n" unless $upstream;

sub handler_curl {
    my $socket = shift;
    my $client_socket = $socket->accept();

    my $data = "";
    $client_socket->recv($data, 4906);

    my $resp = "HTTP/1.0 200 Ok\r\nMyResponseHeader:1\r\nContent-Length:2\r\nConnection: close\r\n\r\nOk";
    $client_socket->send($resp);
    $client_socket->flush;

    close($client_socket);
    return $data;
};


my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        open(CURL, "$curl -HUpper-Case:TheValue -kv $proto://127.0.0.1:$port/ 2>&1 |");
        my $forwarded = handler_curl($upstream);
        my @lines;
        while (<CURL>) {
            push(@lines, $_);

        }
        my $resp = join("", @lines);
        if ($curl =~ /http2/) {
            like($forwarded, qr{upper-case:\s*TheValue}, "Request header name is lowercased");
            like($resp, qr{myresponseheader:\s*1}, "Response header name is lowercase");
        } else {
            like($forwarded, qr{Upper-Case:\s*TheValue}, "Request header name is not lowercased");
            like($resp, qr{MyResponseHeader:\s*1}, "Response header name has case preserved");
        }
    });

done_testing();
