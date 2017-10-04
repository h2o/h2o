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
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $huge_file_size = 50 * 1024 * 1024;
my $huge_file = create_data_file($huge_file_size);

my $doit = sub {
    my ($proto, $opt, $port) = @_;
    my $posts = 10;
    my $out = `nghttp -t 60 $opt -nv -d $huge_file -m $posts $proto://127.0.0.1:$port/echo 2>&1 | grep 'recv WINDOW_UPDATE' | grep -v stream_id=0 | grep -o stream_id=.. | uniq -c | wc -l`;
    chomp($out);
    $out =~ s/\A\s*|\s*\z//;
    is $out, $posts, "No interleaving";
};

subtest 'http (upgrade)' => sub {
    $doit->('http', '-u', $server->{port});
};
subtest 'https' => sub {
    plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
        unless openssl_can_negotiate();
    $doit->('https', '', $server->{tls_port});
};
done_testing();

