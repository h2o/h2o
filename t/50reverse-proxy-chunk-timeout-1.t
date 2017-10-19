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

my $before = time();

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
    h2g.send_data(1, 0, "a"*1000)

    while true do
        f = h2g.read(20000)
        if f == nil
            puts "timeout"
            exit
        end
    end
EOR

my $after = time();

close($nc_out);

ok $after - $before <= 3, "Timeout was triggered by H2O";

done_testing();

