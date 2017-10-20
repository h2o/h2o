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


my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub test {
    my ($iter, $data_size, $sleep, $second_end_stream) = @_;
    my $output = run_with_h2get_simple($server, <<"EOR");
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/echo",
    }
    more = {
        "more" => "headers",
    }

    h2g.send_headers(req, 1, END_HEADERS)
    (1..$iter).each { |c| h2g.send_data(1, 0, "a" * $data_size) }
    h2g.send_headers(more, 1, END_HEADERS|END_STREAM)
    $sleep
    h2g.send_headers(more, 1, END_HEADERS|END_STREAM)

    while true
        f = h2g.read(1000)
        if f == nil
            puts "timeout"
            exit 1
        end
        puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
    end
EOR

    like $output, qr{GOAWAY}, "h2get script got at GOAWAY";
}

foreach my $iter ((1, 10, 100)) {
    foreach my $sleep (("", "sleep 1")) {
        foreach my $data_size ((1, 10000)) {
            foreach my $second_end_stream (("true", "false")) {
                diag("nr DATA packets: $iter, DATA size: $data_size, sleep directive: '$sleep', second END_HEADERS: $second_end_stream");
                test($iter, $data_size, $sleep, $second_end_stream);
            }
        }
    }
}
done_testing();

