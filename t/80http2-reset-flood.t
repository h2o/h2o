use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        - file.dir: @{[ DOC_ROOT ]}
http2-max-concurrent-requests-per-connection: 10
access-log:
  path: $tempdir/access_log
  format: \"%s %b %{http2.stream-id}x\"
EOT

# send 10k requests accompanied by resets
my $output = run_with_h2get_simple($server, <<"EOR");
req = {
    ":method" => "GET",
    ":authority" => host,
    ":scheme" => "https",
    ":path" => "/",
}
loop do
    100000.times do |cnt|
      h2g.send_headers(req, 2 * cnt + 1, END_HEADERS | END_STREAM)
      h2g.send_rst_stream(2 * cnt + 1, 8)
    end
end
EOR

# read logs which is an array of [status_code, body_size, stream_id]
my @logs = do {
    open my $fh, "<", "$tempdir/access_log"
        or die "failed to open file:$tempdir/access_log:$!";
    map { chomp $_; [split / /, $_] } <$fh>;
};
debug(join "\n", map { join " ", @$_ } @logs);

cmp_ok scalar(grep { $_->[0] == 200 } @logs), "<", 500, "ignored most requests";
cmp_ok $logs[-1][2], ">", 100000, "not stalled";

done_testing();
