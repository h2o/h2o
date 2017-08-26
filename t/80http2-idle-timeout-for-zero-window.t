use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 5
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT


my $output = run_with_h2get($server, <<"EOR");
    to_process = []
    h2g = H2.new
    host = ARGV[0] || "localhost:8080"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings([[SETTINGS_INITIAL_WINDOW_SIZE,0]])
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
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/",
    }
    h2g.send_headers(req, 1, END_HEADERS | END_STREAM)
    open_streams = {}
    open_streams[1] = 1
    while open_streams.length > 0
        f = h2g.read(20000)
        if f == nil
          puts "timeout"
          exit 1
        else
          puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        end
        if f.type == "GOAWAY" then
          exit
        end

        if f.type == "DATA" or f.type == "HEADERS" then
            if f.is_end_stream
                open_streams.delete(f.stream_id)
            end
        end
    end
    puts("ok")
EOR
like $output, qr{\nGOAWAY}, "Received a GOAWAY frame";
unlike $output, qr{timeout}, "Script didn't time out";

done_testing();
