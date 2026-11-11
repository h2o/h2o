use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

my $one_shot_upstream = empty_port();
my $g = one_shot_http_upstream("It works!", $one_shot_upstream);
my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+*"
      "/test":
        file.file: /dev/null
num-threads: 1
EOT

my $output = run_with_h2get_simple($server, <<"EOR");
req = {
  ':method' => 'CONNECT',
  ':authority' => "127.0.0.1:$one_shot_upstream",
}
h2g.send_headers(req, 1, END_HEADERS)
h2g.send_data(1, END_STREAM, "")
puts "\n\n\nALL DONE"
# sleep so that the close doesn't race againts the DATA frame
sleep(1)
EOR

like $output, qr{\nALL DONE}, "h2get script finished as expected";

my $resp = `curl -m 5 -ksvo /dev/null https://127.0.0.1:$server->{tls_port}/test 2>&1`;
like $resp, qr{HTTP\/[0-9\.]+ 200}is, "curl, 200 ok";
done_testing();
