use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub doit {
    my $persistent = shift;
    my $upstream_port = empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.timeout.io: 2000
@{[ $persistent ? "" : "proxy.timeout.keepalive: 0" ]}
EOT
    my $port = $server->{port};
    my $res = `curl --max-time 5 --silent --dump-header /dev/stderr http://127.0.0.1:$port/ 2>&1 > /dev/null`;
    like $res, qr{^HTTP/1\.1 502 }, "502 response on upstream error";
};

subtest 'non-persistent' => sub {
    doit(0);
};

subtest 'persistent' => sub {
    doit(1);
};

# The request body is not read any further once the connection to upstream fails. Otherwise, the HTTP/2 stream would continue to
# occupy the slot for streaming requests, blocking the next one sent on the same connection.
subtest 'streaming request body' => sub {
    my $upstream_port = empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my $output = run_with_h2get_simple($server, <<"EOR");
        [1, 3].each { |stream_id|
            req = { ":method" => "POST", ":authority" => host, ":scheme" => "https", ":path" => "/" }
            h2g.send_headers(req, stream_id, END_HEADERS)
            h2g.send_data(stream_id, 0, "a" * 1000)
        }
        while true
            f = h2g.read(2000)
            break if f == nil
            puts "stream:#{f.stream_id}" if f.type == "HEADERS"
            puts f.to_s
        end
EOR
    for my $stream_id (1, 3) {
        like $output, qr{^stream:$stream_id\n.*?':status' => '502'}ms, "stream $stream_id";
    }
};

done_testing();
