use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);


my $server = spawn_h2o(<< "EOT");
http2-max-concurrent-requests-per-connection: 12
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $huge_file_size = 20 * 1024;
my $huge_file = create_data_file($huge_file_size);

my $doit = sub {
    my ($proto, $port) = @_;
    my $posts = 100;
    my $cmd = "h2load -N 5s -m $posts -n $posts -d $huge_file $proto://127.0.0.1:$port/echo 2>&1";
    print($cmd);
    my $out = `$cmd`;
    like $out, qr{status codes: $posts 2xx}, "No error on exit";
};

subtest 'https' => sub {
    plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
        unless openssl_can_negotiate();
    $doit->('https', $server->{tls_port});
};
done_testing();
