use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'start_server not found'
    unless prog_exists('start_server');

my $server = spawn_h2o(sub {
    my ($port, $tls_port) = @_;
    return +{
        prefix => [ "start_server", "--port=0.0.0.0:$port", "--port=0.0.0.0:$tls_port", "--" ],
        conf   => << "EOT",
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    };
});

subtest 'before-HUP' => sub {
    fetch_test();
};
kill 'HUP', $server->{pid};
sleep 1;
subtest 'after-HUP' => sub {
    fetch_test();
};

done_testing;

sub fetch_test {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $doit = sub {
        my ($proto, $port) = @_;
        my $content = `curl --silent --show-error --insecure $proto://127.0.0.1:$port/`;
        is md5_hex($content), md5_file(DOC_ROOT . "/index.txt"), $proto;
    };
    $doit->("http", $server->{port});
    $doit->("https", $server->{tls_port});
}
