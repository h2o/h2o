use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $upstream = spawn_server(
    argv => [
        qw(plackup -s Starlet --max-workers 10 --access-log /dev/null --listen), "$tempdir/upstream.sock",
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub { !! -e "$tempdir/upstream.sock" },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://[unix:$tempdir/upstream.sock]/
EOT

my $out = `nghttp -nv https://127.0.0.1:$server->{tls_port}/content`;
like $out, qr{:status: 200}, "200 OK";
like $out, qr{HEADERS.*flags=0x05}, "The headers frame contains and end of stream flag";

done_testing();
