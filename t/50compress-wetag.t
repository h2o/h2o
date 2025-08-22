use strict;
use warnings;
use Net::EmptyPort qw(check_port);
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

sub fetch {
    my ($msg, $x_compress_header, $resp_content_encoding, $etag) = @_;

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

    do { local $/; <$curl> };
}

subtest "identity + strong" => sub {
    my $resp = fetch("The compressed response", "x-compress-hint: on", undef, "theetag");
    like $resp, qr{^<\s*etag:\s*W/theetag\s*}im;
};
subtest "identity + weak" => sub {
    my $resp = fetch("The compressed response", "x-compress-hint: on", undef, "W/theetag");
    like $resp, qr{^<\s*etag:\s*W/theetag\s*}im;
};
subtest "gzip + strong" => sub {
    my $resp = fetch("The compressed response", "x-compress-hint: on", "gzip", "theetag");
    like $resp, qr{^<\s*etag:\s*theetag\s*}im;
};
subtest "gzip + weak" => sub {
    my $resp = fetch("The compressed response", "x-compress-hint: on", "gzip", "W/theetag");
    like $resp, qr{^<\s*etag:\s*W/theetag\s*}im;
};

$upstream_listener->close();
undef $server;

done_testing();
