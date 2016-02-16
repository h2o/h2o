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

run_with_curl($server, sub {
    my ($proto, $port, $curl_cmd) = @_;
    $curl_cmd .= " --silent --show-error";
    my $url = "$proto://127.0.0.1:$port/halfdome.jpg";

    subtest "non-ranged" => sub {
        my $resp = `$curl_cmd $url`;
        is $resp, $all_data;
    };

    subtest "single-ranged" => sub {
        subtest "closed" => sub {
            my $resp = `$curl_cmd -r 100-499 $url`;
            is $resp, substr($all_data, 100, 400), "content";

            my $headers = `$curl_cmd -r 100-499 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
            like $headers, qr{^content-type:\s*image/jpeg\r$}mi, "content-type";
            like $headers, qr{^content-range:\s*bytes 100-499/@{[length $all_data]}\r}mi, "content-range";
        };

        subtest "closed-exceed-end" => sub {
            my $resp = `$curl_cmd -r 100-999999 $url`;
            is $resp, substr($all_data, 100), "content";

            my $headers = `$curl_cmd -r 100-999999 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
            like $headers, qr{^content-type:\s*image/jpeg\r$}mi, "content-type";
            like $headers, qr{^content-range:\s*bytes 100-@{[length($all_data) - 1]}/@{[length $all_data]}\r}mi, "content-range";
        };

        subtest "closed-unsatisfied" => sub {
            my $headers = `$curl_cmd --dump-header /dev/stderr -r 999999-999999 $url 2>&1 > /dev/null`;
            like $headers, qr{^HTTP/[^ ]+ 416\s}mi, "416 response";
        };

        subtest "tail-open" => sub {
            my $resp = `$curl_cmd -r 100- $url`;
            is $resp, substr($all_data, 100), "content";

            my $headers = `$curl_cmd -r 100- --dump-header /dev/stderr $url 2>&1 > /dev/null`;
            like $headers, qr{^content-type:\s*image/jpeg\r$}mi, "content-type";
            like $headers, qr{^content-range:\s*bytes 100-@{[length($all_data) - 1]}/@{[length $all_data]}\r}mi, "content-range";
        };

        subtest "suffix" => sub {
            my $resp = `$curl_cmd -r -100 $url`;
            is $resp, substr($all_data, -100), "content";

            my $headers = `$curl_cmd -r -100 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
            like $headers, qr{^content-type:\s*image/jpeg\r$}mi, "content-type";
            like $headers, qr{^content-range:\s*bytes @{[length($all_data) - 100]}-@{[length($all_data) - 1]}/@{[length $all_data]}\r}mi, "content-range";
        };

        subtest "suffix-exceed" => sub {
            my $resp = `$curl_cmd -r -999999 $url`;
            is $resp, $all_data, "content";

            my $headers = `$curl_cmd -r -999999 --dump-header /dev/stderr $url 2>&1 > /dev/null`;
            like $headers, qr{^content-type:\s*image/jpeg\r$}mi, "content-type";
            like $headers, qr{^content-range:\s*bytes 0-@{[length($all_data) - 1]}/@{[length $all_data]}\r}mi, "content-range";
        };
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
        like $headers, qr{^content-type:\s*multipart/byteranges; boundary=[0-9A-Za-z]{20}\r$}mi, "content-type";
    };
});

done_testing();
