use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

# spawn upstream
my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);
my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
http2-max-streams: 1000
http2-max-concurrent-requests-per-connection: 10000
access-log:
  path: $tempdir/access_log
  format: \"%s %b %{http2.stream-id}x\"
EOT

# Start 1k concurrent requests by sending 1k POST headers followed by 1k DATA END_STREAMs.
my $output = run_with_h2get_simple($server, <<"EOR");
    N = 1000

    puts "Send HEADERS"
    (0..(N-1)).each { |it|
      stream_id = 2*it + 1
      req = {
        ":method" => "POST",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/echo",
      }
      h2g.send_headers(req, stream_id, END_HEADERS)
    }

    puts "Send END_STREAM in reverse stream id order"
    (0..N-1).each { |it|
      stream_id = 2*(N-1-it) + 1
      h2g.send_data(stream_id, END_STREAM, "a")
    }

    header_count = 0
    remaining = N
    while remaining > 0
      frame = h2g.read(-1)
      puts frame
      if frame.type == "RST_STREAM"
        puts "ERROR: the remote end sent RST_STREAM"
        exit 2
      end
      if frame.type == "GO_AWAY"
        puts "ERROR: the remote end sent GO_AWAY"
        exit 2
      end
      if frame.type == "HEADERS"
        header_count += 1
      end
      if frame.type == "DATA" and frame.len > 0
        h2g.send_window_update(0, frame.len)
        h2g.send_window_update(frame.stream_id, frame.len)
      end
      if frame.type == "DATA" and frame.is_end_stream
        remaining -= 1
        puts "=> Remaining #{remaining}"
      end
    end

    puts "\n\n\nALL DONE"
EOR

like $output, qr{\nALL DONE}, "h2get script finished as expected";

# read logs which is an array of [status_code, body_size, stream_id]
my @logs = do {
    open my $fh, "<", "$tempdir/access_log"
        or die "failed to open file:$tempdir/access_log:$!";
    map { chomp $_; [split / /, $_] } <$fh>;
};
debug(join "\n", map { join " ", @$_ } @logs);

is scalar(grep { $_->[0] == 200 } @logs), 1000, "accepted all requests";

done_testing();
