use strict;
use warnings;
use File::Temp qw(tempdir);
use JSON qw(decode_json);
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

# spawn server
my $server = spawn_h2o(<< "EOT");
http3-idle-timeout: 3
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        file.dir: t/assets/doc_root
      "/proxy":
        proxy.reverse.url: http://[unix:$tempdir/upstream.sock]/
      "/status":
        status: ON
EOT
wait_port({port => $quic_port, proto => 'udp'});

my $num_conns = sub {
    my $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/status/json?show=main' 2>&1 > /dev/null`;
    my $json = decode_json($resp);
    $json->{'connections'};
};

# connect, check that the client disconnects and reconnects
subtest "idle-timeout-reconnect" => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    # spawn client that fetches twice with an interval greater than the idle timeout
    open my $client_fh, "-|", "$client_prog -3 100 -d 6000 -t 2 https://127.0.0.1:$quic_port/ 2> /dev/null"
        or die "failed to spawn $client_prog:$!";

    sleep 1;
    is $num_conns->(), 2, "h3 connection still alive";
    sleep 4;
    is $num_conns->(), 1, "h3 connection closed after idle timeout";

    # read the output from client, check that the file is fetched twice
    is do {local $/; join "", <$client_fh>}, "hello\n" x 2, "h3 client reconnected";
};

subtest "too-early" => sub {
    my $upstream = spawn_server(
        argv => [
            qw(plackup -s Starlet --max-workers 2 --access-log /dev/null --listen), "$tempdir/upstream.sock",
            ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub { !! -e "$tempdir/upstream.sock" },
    );
    open my $client_fh, "-|", "$client_prog -3 100 -d 5000 -t 2 https://127.0.0.1:$quic_port/proxy/425 2>&1"
        or die "failed to spawn $client_prog:$!";
    like do {local $/; join "", <$client_fh>}, qr{^HTTP/[0-9\.]+ 200.*\nhello\nHTTP/[0-9\.]+ 425}s, "2nd response is 425";
};

done_testing;
