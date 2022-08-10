use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $sock = "$tempdir/upstream.sock";

# curl -> h2o -> h2o -> plackup
my $backend = spawn_server(
    argv => [
        qw(plackup -s Starlet --max-workers 10 --access-log /dev/null --listen), $sock,
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub { !! -e $sock },
);

my $upstream = spawn_h2o(<<EOT);
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://[unix:$sock]/
EOT

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: https://127.0.0.1:$upstream->{tls_port}/
        proxy.ssl.verify-peer: OFF
EOT

sleep 1;

for my $size (1, 100, 1_000, 10_000, 100_000, 1_000_000) {
    my $file = "$tempdir/body.$size";
    my $bytes = "*" x $size;
    open my $fh, ">", $file;
    print $fh $bytes;
    close $fh;

    for (1..10) {
        my $output = `curl -XPOST -d \@$file -sk --http2 https://127.0.0.1:$server->{tls_port}/echo`;
        is length($output), $size, "request body $size bytes"
          and is $output, $bytes;
    }
}

done_testing();
