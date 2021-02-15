use strict;
use warnings;
use Test::More;
use Net::EmptyPort qw(check_port empty_port);
use t::Util;

my $origin_port = empty_port();
my $origin = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $origin_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($origin_port);
    },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.connect: ON
        proxy.timeout.io: 2000
EOT

my $ok_resp = qr{HTTP/[^ ]+ 200\s}m;

subtest "simple HTTP/1.1 proxied request", sub {
    my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/echo 2>&1`;
    like $content, qr{Proxy replied 200 to CONNECT request}m, "Connect got a 200 response to CONNECT";
    my @c = $content =~ /$ok_resp/g;
    is @c, 2, "Got two 200 responses";
};

subtest "Forward proxy timeout", sub {
    my $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/sleep-and-respond?sleep=1 2>&1`;
    like $content, qr{Proxy replied 200 to CONNECT request}m, "Connect got a 200";
    my @c = $content =~ /$ok_resp/g;
    is @c, 2, "Got two 200 responses, no timeout";

    $content = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent -v --show-error http://127.0.0.1:$origin_port/sleep-and-respond?sleep=10 2>&1`;
    like $content, qr{Proxy replied 200 to CONNECT request}m, "Connect got a 200";
    @c = $content =~ /$ok_resp/g;
    is @c, 1, "Only got one 200 response";
};

done_testing;
