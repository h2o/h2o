use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $upstream_port = empty_port();
$| = 1;
my $upstream_listener = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
) or die "cannot create socket $!\n";

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

    open(
        my $curl,
        "-|",
        "curl -Haccept-encoding:br,gzip -Hhost:host.example.com -svo /dev/null http://127.0.0.1:$server->{'port'}/ 2>&1",
    ) or die "failed to launch curl:$!";

    my $conn = $upstream_listener->accept();
    $conn->recv(my $req, 1024);
    my @resp = ("HTTP/1.1 200 OK", "Connection: close", "Content-Length: " . length $msg, "ETag: $etag");
    push @resp, "Content-Encoding: $resp_content_encoding"
        if $resp_content_encoding;
    push @resp, $x_compress_header
        if $x_compress_header;
    push @resp, "", $msg; # empty line and the response body
    $conn->send(join "\r\n", @resp);
    close($conn);

    my $seen_etag = "";
    while(<$curl>) {
        if (/< etag: (.*)\r\n/i) {
            $seen_etag = $1;
        }
    }

    ok($seen_etag eq $expect_etag, "The seen etag header (".$seen_etag.") was the one expected (".$expect_etag.")");
}


doit("The compressed response", "x-compress-hint: on", undef, "theetag", "W/theetag");
doit("The compressed response", "x-compress-hint: on", undef, "W/theetag", "W/theetag");
doit("The compressed response", "x-compress-hint: on", "gzip", "theetag", "theetag");
doit("The compressed response", "x-compress-hint: on", "gzip", "W/theetag", "W/theetag");



$upstream_listener->close();
done_testing();
