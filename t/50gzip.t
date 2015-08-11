use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /off:
        file.dir: @{[DOC_ROOT]}
      /on:
        file.dir: @{[DOC_ROOT]}
        gzip: ON
EOT

my $doit = sub {
    my ($proto, $port) = @_;
    my $fetch_orig = sub {
        my ($path, $opts) = @_;
        run_prog("curl --silent --insecure $opts $proto://127.0.0.1:$port$path/alice.txt");
    };
    my $fetch_gunzip = sub {
        my ($path, $opts) = @_;
        run_prog("curl --silent --insecure $opts $proto://127.0.0.1:$port$path/alice.txt | gzip -cd");
    };
    my $expected = md5_file("@{[DOC_ROOT]}/alice.txt");

    my $resp = $fetch_orig->("/off", "");
    is md5_hex($resp), $expected, "off wo. accept-encoding";
    $resp = $fetch_orig->("/on", "");
    is md5_hex($resp), $expected, "on wo. accept-encoding";
    $resp = $fetch_orig->("/off", "-H accept-encoding:gzip");
    is md5_hex($resp), $expected, "off with accept-encoding";
    $resp = $fetch_gunzip->("/on", "-H accept-encoding:gzip");
    is md5_hex($resp), $expected, "on with accept-encoding";
    $resp = $fetch_gunzip->("/on", "-H 'accept-encoding:gzip, deflate'");
    is md5_hex($resp), $expected, "on with accept-encoding: gzip,deflate";
    $resp = $fetch_gunzip->("/on", "-H 'accept-encoding:deflate, gzip'");
    is md5_hex($resp), $expected, "on with accept-encoding: deflate, gzip";
    $resp = $fetch_orig->("/on", "-H accept-encoding:deflate");
    is md5_hex($resp), $expected, "on with accept-encoding, deflate only";

    $resp = run_prog("curl --silent --insecure -H accept-encoding:gzip $proto://127.0.0.1:$port/on/halfdome.jpg");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "image not compressed";
};

subtest 'http' => sub {
    $doit->('http', $server->{port});
};
subtest 'https' => sub {
    $doit->('https', $server->{tls_port});
};

undef $server;

done_testing();
