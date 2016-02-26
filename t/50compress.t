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
        compress: ON
      /off-by-mime:
        file.dir: @{[DOC_ROOT]}
        compress: ON
        file.mime.settypes:
          text/plain:
            extensions: [".txt"]
            is_compressible: NO
      /compress-jpg:
        file.dir: @{[DOC_ROOT]}
        compress: ON
        file.mime.settypes:
          image/jpg:
            extensions: [".jpg"]
            is_compressible: YES
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    plan skip_all => 'curl issue #661'
        if $curl =~ /--http2/;
    my $fetch_orig = sub {
        my ($path, $opts) = @_;
        run_prog("$curl --silent $opts $proto://127.0.0.1:$port$path/alice.txt");
    };
    my $fetch_gunzip = sub {
        my ($path, $opts) = @_;
        run_prog("$curl --silent $opts $proto://127.0.0.1:$port$path/alice.txt | gzip -cd");
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
    is md5_hex($resp), $expected, "on with accept-encoding: gzip, deflate";
    $resp = $fetch_gunzip->("/on", "-H 'accept-encoding:deflate, gzip'");
    is md5_hex($resp), $expected, "on with accept-encoding: deflate, gzip";
    $resp = $fetch_orig->("/on", "-H accept-encoding:deflate");
    is md5_hex($resp), $expected, "on with accept-encoding, deflate only";

    $resp = $fetch_orig->("/off-by-mime", "-H accept-encoding:gzip");
    is md5_hex($resp), $expected, "off due to is_compressible:NO";

    $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/on/index.txt");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/index.txt"), "tiny file not compressed";

    $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/on/halfdome.jpg");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "image not compressed";

    $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/compress-jpg/halfdome.jpg | gzip -cd");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "image compressed using gzip";

    subtest "brotli-decompress" => sub {
        plan skip_all => "bro not found"
            unless prog_exists("bro");
        $resp = run_prog("$curl --silent -H accept-encoding:br $proto://127.0.0.1:$port/on/alice.txt | bro --decompress");
        is md5_hex($resp), md5_file("@{[DOC_ROOT]}/alice.txt"), "alice.txt";
        $resp = run_prog("$curl --silent -H accept-encoding:br $proto://127.0.0.1:$port/compress-jpg/halfdome.jpg | bro --decompress");
        is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "halfdome.jpg";
    };
});

undef $server;

done_testing();
