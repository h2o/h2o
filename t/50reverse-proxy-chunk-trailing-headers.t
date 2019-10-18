use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $upstream_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 10
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub test {
    my $delay = shift;
    my ($stderr, $stdout) = run_with_h2get($server, <<"EOR");
    to_process = []
    h2g = H2.new
    authority = ARGV[0]
    host = "https://#{authority}"
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
    sleep $delay
    h2g.send_data(1, 0, "a"*1000)
    sleep $delay
    req = {
        "date" => "Wed Apr 26 11:57:54 PDT 2017"
    }
    h2g.send_headers(req, 1, END_STREAM | END_HEADERS)

    while true do
        f = h2g.read(5000)
        if f == nil
            puts "timeout"
            exit
        end

        puts f.type
        exit if f.type == "DATA"
    end
EOR

    like $stdout, qr{HEADERS\nDATA\n}, "Received a response, no timeout or error\n";
}

test(0);
test(1);
done_testing();

