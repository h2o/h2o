use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $upstream = spawn_server(
    argv => [
        qw(plackup -s Starlet --max-workers 10 --access-log /dev/null --listen), "$tempdir/upstream.sock",
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub { !! -e "$tempdir/upstream.sock" },
);
sleep 1;

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://[unix:$tempdir/upstream.sock]/
EOT

# send 3 requests to /suspend-body, check that all the header fields are received before the content
sub fetch3 {
    my $opts = shift;
    open my $client_fh, "-|", "$client_prog -3 -C 3 -t 3 $opts https://127.0.0.1:$quic_port/suspend-body 2>&1"
        or die "failed to spawn $client_prog:$!";
    local $/;
    join "", <$client_fh>;
}

my $resp_concurrent = qr!^(?:HTTP/[0-9\.]+ 200.*?\n\n){3}x{3}$!s;
my $resp_sequential = qr!^(?:HTTP/[0-9\.]+ 200.*?\n\nx){3}$!s;

like fetch3(""), $resp_concurrent, "GETs are concurrent";
like fetch3("-m POST -b 10000 -c 100 -i 50"), $resp_concurrent, "POST of 10KB (taking 5 seconds) is concurrent";
like fetch3("-m POST -b 1000000 -c 10000 -i 50"), $resp_sequential, "POST of 1MB (taking 5 seconds) is not concurrent";

done_testing;
