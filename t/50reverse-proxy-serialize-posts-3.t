use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => "nc not found"
    unless prog_exists("nc");

my $upstream_port = empty_port();
$| = 1;

open(my $nc_out, "nc -dl $upstream_port |");

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

# This H2 client sends a partial request (no END_STREAM flag is ever set
# with a DATA frame).
#
# The test then checks that the request partially made it to the
# upstream nc server by counting the size of the chunks, in order to
# demonstrate that we are indeed streaming the body

my $output = run_with_h2get($server, <<"EOR");
    to_process = []
    h2g = H2.new
    host = ARGV[0]
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings()
    i = 0
    while i < 2 do
        f = h2g.read(-1)
        if f.type == "SETTINGS" and (f.flags == ACK) then
            i += 1
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
            i += 1
        end
    end

    req = {
        ":method" => "POST",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/streaming-test",
    }
    h2g.send_headers(req, 1, END_HEADERS)
    (1..5).each { |c|
        h2g.send_data(1, 0, "a"*1000)
    }
    sleep 5;
EOR

my $resp;
while (<$nc_out>) {
    $resp = $resp . $_;
}
my ($headers, $body) = split /\r\n\r\n/, $resp;

my $chunked_header_found = 0;
foreach my $h (split /\r\n/, $headers) {
    if ($h =~ /transfer-encoding: chunked/) {
        $chunked_header_found = 1;
    }
}
ok($chunked_header_found == 1, "TE:chunked header found");

my @chunks = split /\r\n/, $body;

my $chunk_len = 0;
for (my $i = 0; $i < length(@chunks); $i+=3) {
    $chunk_len += hex($chunks[$i]);
}

ok $chunk_len == 5000, "Found the partially transferred request";

done_testing();

