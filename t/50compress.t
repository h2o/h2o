use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;
use File::Temp qw(tempfile);

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
        run_prog("$curl --silent --dump-header /dev/stderr $opts $proto://127.0.0.1:$port$path/alice.txt");
    };
    my $fetch_gunzip = sub {
        my ($path, $opts) = @_;
        my ($tempfh, $tempfn) = tempfile(UNLINK => 1);
        my $headers = `$curl --silent --dump-header /dev/stderr $opts $proto://127.0.0.1:$port$path/alice.txt 2>&1 > $tempfn`;
        my $body = `cat $tempfn | gzip -cd`;
        close $tempfh;
        ($headers, $body);
    };

    my $expected = md5_file("@{[DOC_ROOT]}/alice.txt");
    my $expected_etag = etag_file("@{[DOC_ROOT]}/alice.txt");
    my ($headers, $body) = $fetch_orig->("/off", "");
    is md5_hex($body), $expected, "off wo. accept-encoding";
    like $headers, qr{^etag: $expected_etag\r$}im, "it has an etag";
    ($headers, $body) = $fetch_orig->("/on", "");
    is md5_hex($body), $expected, "on wo. accept-encoding";
    like $headers, qr{^etag: $expected_etag\r$}im, "it has an etag";
    ($headers, $body) = $fetch_orig->("/off", "-H accept-encoding:gzip");
    is md5_hex($body), $expected, "off with accept-encoding";
    like $headers, qr{^etag: $expected_etag\r$}im, "it has an etag";
    ($headers, $body) = $fetch_gunzip->("/on", "-H accept-encoding:gzip");
    is md5_hex($body), $expected, "on with accept-encoding";
    like $headers, qr{^etag: W/$expected_etag\r$}im, "it has a weak etag";
    ($headers, $body) = $fetch_gunzip->("/on", "-H 'accept-encoding:gzip, deflate'");
    is md5_hex($body), $expected, "on with accept-encoding: gzip, deflate";
    like $headers, qr{^etag: W/$expected_etag\r$}im, "it has a weak etag";
    ($headers, $body) = $fetch_gunzip->("/on", "-H 'accept-encoding:deflate, gzip'");
    is md5_hex($body), $expected, "on with accept-encoding: deflate, gzip";
    like $headers, qr{^etag: W/$expected_etag\r$}im, "it has a weak etag";
    ($headers, $body) = $fetch_orig->("/on", "-H accept-encoding:deflate");
    is md5_hex($body), $expected, "on with accept-encoding, deflate only";
    like $headers, qr{^etag: $expected_etag\r$}im, "it has an etag";

    ($headers, $body) = $fetch_orig->("/off-by-mime", "-H accept-encoding:gzip");
    is md5_hex($body), $expected, "off due to is_compressible:NO";

    my $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/on/index.txt");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/index.txt"), "tiny file not compressed";

    $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/on/halfdome.jpg");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "image not compressed";

    $resp = run_prog("$curl --silent -H accept-encoding:gzip $proto://127.0.0.1:$port/compress-jpg/halfdome.jpg | gzip -cd");
    is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "image compressed using gzip";

    subtest "brotli-decompress" => sub {
        plan skip_all => "brotli not found"
            unless prog_exists("brotli");
        $resp = run_prog("$curl --silent -H accept-encoding:br $proto://127.0.0.1:$port/on/alice.txt | brotli --decompress");
        is md5_hex($resp), md5_file("@{[DOC_ROOT]}/alice.txt"), "alice.txt";
        $resp = run_prog("$curl --silent -H accept-encoding:br $proto://127.0.0.1:$port/compress-jpg/halfdome.jpg | brotli --decompress");
        is md5_hex($resp), md5_file("@{[DOC_ROOT]}/halfdome.jpg"), "halfdome.jpg";
    };
});

undef $server;

done_testing();
