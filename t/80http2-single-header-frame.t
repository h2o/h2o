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
http2-idle-timeout: 3
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://[unix:$tempdir/upstream.sock]/
EOT

my ($stderr,$stdout) = run_with_h2get_simple($server, <<"EOS");
    req = { ":method" => "GET", ":authority" => authority, ":scheme" => "https", ":path" => "/content" }
    h2g.send_headers(req, 1, END_HEADERS | END_STREAM)
    f = h2g.read(-1)
    puts f.to_s
    f = h2g.read(-1)
    puts "last=#{f.type}" unless f == nil
EOS
like $stderr, qr{^$}, "stderr is empty";
like $stdout, qr{':status' => '200'}, "200 OK";
like $stdout, qr{HEADERS.*flags=0x05}, "The headers frame contains and end of stream flag";
like $stdout, qr{last=GOAWAY}, "GOAWAY frame sent by h2o";

done_testing();
