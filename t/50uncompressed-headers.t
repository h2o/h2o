use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

# 'Cookie' field should be compressed (>= 20-bytes)
# 'Set-Cookie' field should not be compressed (< 20-bytes)
my $server = spawn_h2o(<< "EOT");
header.add: "Cookie: ABCDEFGHIJKLMNOPQRSTUVWXYZsjdfisjfidjsfisdjfsijfidsjfidsjfij"
header.add: "Set-Cookie: foo=bar; bar=baz;"
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

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
        ":path" => "/echo-headers",
    }
    h2g.send_headers(req, 1, END_HEADERS)
    h2g.send_headers(req, 3, END_HEADERS)
    (1..30).each { |c|
        h2g.send_data(1, 0, "a"*10000)
        h2g.send_data(3, 0, "a"*10000)
    }
    h2g.send_data(1, END_STREAM, "end")
    h2g.send_data(3, END_STREAM, "end")

    open_streams = {}
    open_streams[1] = 1
    open_streams[3] = 1
    max_stream_id = 0
    while open_streams.length > 0
        f = h2g.read(20000)
        if f == nil
          puts "timeout"
          exit 1
        else
          puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        end
        if f.type == "HEADERS" then
            puts f.to_s
        end
        if f.type == "DATA" or f.type == "HEADERS" then
            if f.type == "DATA" and f.len > 0
                h2g.send_window_update(0, f.len)
                h2g.send_window_update(f.stream_id, f.len)
            end
            if f.is_end_stream
                open_streams.delete(f.stream_id)
            end
        end
    end
    puts("ok")
EOR

like $output, qr{\nok}, "h2get script finished as expected";
like $output, qr{cookie.*ABCDEFGHIJKLMNOPQRSTUVWXYZsjdfisjfidjsfisdjfsijfidsjfidsjfij}, "'cookie' value as expected";
like $output, qr{set-cookie.*foo\=bar\; bar\=baz\;}, "'set-cookie' value as expected";
like $output, qr{compressed.*'cookie'}, "'cookie' was compressed";
unlike $output, qr{compressed.*'set-cookie'}, "'set-cookie' was not compressed";

done_testing();
