use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

my $upstream_port = empty_port();
$| = 1;

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $before = time();


my $huge_file_size = 100 * 1024 * 1024;
my $huge_file = create_data_file($huge_file_size);

my $doit = sub {
    my ($proto, $opt, $port) = @_;

    open(my $nc_out, "nc -q -1 -dl $upstream_port |");

    my $before = time();
    `nghttp -t 10 $opt -nv -d $huge_file $proto://127.0.0.1:$port/echo`;
    my $after = time();
    ok $after - $before >= 10, "Timeout was triggered by nghttp";

    close($nc_out);
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

