use strict;
use warnings;
use Test::More;
use t::Util;
use Time::HiRes qw(time);

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $all_data = do {
    open my $fh, "<", "@{[DOC_ROOT]}/halfdome.jpg"
        or die "failed to open file:@{[DOC_ROOT]}/halfdome.jpg:$!";
    undef $/;
    <$fh>;
};

my $server = spawn_h2o(<< "EOT");
throttle-response: ON
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
        header.add: "X-Traffic: 100000"
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl_cmd) = @_;
    $curl_cmd .= " --silent --show-error";
    my $url = "$proto://127.0.0.1:$port/halfdome.jpg";

    subtest "throttle-to-low-speed" => sub {
        my $start_time = time;
        my $resp = `$curl_cmd $url`;
        my $end_time = time;
        is $resp, $all_data;
        my $speed = length($resp) / ($end_time - $start_time);
        cmp_ok($speed, '<=', 100000 * 1.1); # the implementation may cause response speed is a bit larger than the limitation, especially when file is not big enough.
    };
});

done_testing();
