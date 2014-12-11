use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

our $CA_CERT = "misc/test-ca/ca.crt";

# using wget since curl of OS X 10.9.5 returns invalid certificate chain error with the test
plan skip_all => 'wget not found'
    unless prog_exists('wget');

my $server = spawn_h2o(sub {
    my ($port, $tls_port) = @_;
    return << "EOT";
hosts:
  "127.0.0.1.xip.io:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
  "alternate.127.0.0.1.xip.io:$tls_port":
    listen:
      port: $tls_port
      ssl:
        key-file: examples/h2o/alternate.key
        certificate-file: examples/h2o/alternate.crt
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
});

subtest 'default-host' => sub {
    do_test(
        "127.0.0.1.xip.io:$server->{tls_port}",
        md5_file("examples/doc_root/index.html"),
    );
};
subtest 'alternate-host' => sub {
    do_test(
        "alternate.127.0.0.1.xip.io:$server->{tls_port}",
        md5_file("examples/doc_root.alternate/index.txt"),
    );
};

done_testing();

sub do_test {
    my ($authority, $md5_expected) = @_;
    my $content = `wget -nv --ca-certificate=$CA_CERT -O - https://$authority/`;
    is $?, 0, "wget returns success";
    is md5_hex($content), $md5_expected, "content is as expected";
}
