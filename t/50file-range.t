use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $all_data = do {
    open my $fh, "<", "@{[DOC_ROOT]}/halfdome.jpg"
        or die "failed to open file:@{[DOC_ROOT]}/halfdome.jpg:$!";
    undef $/;
    <$fh>;
};

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

my $curl_cmd = "curl --silent --show-error --insecure";
my $url = "http://127.0.0.1:$server->{port}/halfdome.jpg";

subtest "non-ranged" => sub {
    my $resp = `$curl_cmd $url`;
    is $resp, $all_data;
};

subtest "singe-ranged" => sub {
    my $resp = `$curl_cmd -r 100-499 $url`;
    is $resp, substr($all_data, 100, 400), "content";

    my $headers = `$curl_cmd -r 100-499 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
    like $headers, qr{^content-type: image/jpeg\r$}mi, "content-type";
    like $headers, qr{^content-range: bytes 100-499/@{[length $all_data]}\r}mi, "content-range";
};

subtest "multi-ranged" => sub {
    my $resp = `$curl_cmd -r 100-199,1000-1099 $url`;
    my @chunks = split /(?:^|\r\n)--[0-9A-Za-z]{20}/s, $resp;
    is scalar(@chunks), 4, "number of ranges";
    is $chunks[0], "", "before first boundary";
    is substr($chunks[1], -104), "\r\n\r\n" . substr($all_data, 100, 100), "first chunk";
    is substr($chunks[2], -104), "\r\n\r\n" . substr($all_data, 1000, 100), "second chunk";
    is $chunks[3], "--\r\n", "last boundary";

    my $headers = `$curl_cmd -r 100-199,1000-1099 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
    like $headers, qr{^content-type: multipart/byteranges; boundary=[0-9A-Za-z]{20}\r$}mi, "content-type";
};

done_testing();
