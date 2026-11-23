use strict;
use warnings;
use File::Temp qw(tempdir tempfile);
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

# Tests that the HTTP/3 client stops receiving the response when the amount of data being buffered reaches `proxy.max-buffer-size`.
# Responses are requested using h2get, which stops sending WINDOW_UPDATE frames thereby blocking the proxy by the flow control of
# HTTP/2, and whether the upstream has completed sending the response is checked using the access log of the upstream.

my $tempdir = tempdir(CLEANUP => 1);
my $large_size = 8 * 1024 * 1024;  # larger than the stream-level receive window of the HTTP/3 client
my $small_size = 512 * 1024;       # smaller than the stream-level receive window of the HTTP/3 client

{
    open my $fh, ">", "$tempdir/large"
        or die "failed to create $tempdir/large:$!";
    print $fh "x" x $large_size;
    close $fh;
}

# Sends a request, reads the response until the proxy stops sending due to flow control, prints "stalled", stalls for the given
# duration, then reads the rest of the response and prints the outcome.
my ($scriptfh, $scriptfn) = tempfile(UNLINK => 1);
print $scriptfh <<'EOR';
STDOUT.sync = true
authority, path, expected_char, stall_ms = ARGV[0], ARGV[1], ARGV[2], ARGV[3].to_i
h2g = H2.new
h2g.connect("https://#{authority}")
h2g.send_prefix()
h2g.send_settings()
h2g.send_headers({":method" => "GET", ":authority" => authority, ":scheme" => "https", ":path" => path}, 1, END_HEADERS | END_STREAM)

status = nil
length = 0
content_ok = true
handle_frame = lambda do |f|
  if f.type == "SETTINGS" && f.flags != ACK
    h2g.send_settings_ack()
  elsif f.type == "HEADERS" && f.stream_id == 1
    status = f.to_s.include?("':status' => '200'") ? "200" : f.to_s
  elsif f.type == "DATA" && f.stream_id == 1
    payload = f.payload
    length += payload.length
    content_ok &&= payload == expected_char * payload.length
    return f.is_end_stream
  end
  false
end

while (f = h2g.read(1000)) != nil
  handle_frame.call(f)
end
puts "stalled"
while (f = h2g.read(stall_ms)) != nil
  handle_frame.call(f)
end

h2g.send_window_update(0, length)
h2g.send_window_update(1, length)
while true
  f = h2g.read(10000)
  break if f == nil
  done = handle_frame.call(f)
  if f.type == "DATA" && f.len > 0
    h2g.send_window_update(0, f.len)
    h2g.send_window_update(1, f.len)
  end
  break if done
end
puts "status=#{status} length=#{length} content=#{content_ok ? "ok" : "ng"}"
h2g.close
EOR
close $scriptfh;

subtest "default" => sub {
    my $env = setup("");
    my $req = start_request($env, "/large", "x", 6000);
    my $completed;
    for (1..55) {
        last if $completed = upstream_completed($env);
        sleep 0.1;
    }
    ok $completed, "upstream completed sending the response while the client was stalled";
    test_response($req, $large_size);
};

subtest "max-buffer-size" => sub {
    my $env = setup("proxy.max-buffer-size: 65536");
    my $req = start_request($env, "/large", "x", 5000);
    sleep 2;
    ok !upstream_completed($env), "upstream did not complete sending the response while the client was stalled";
    test_response($req, $large_size);
    for (1..50) {
        last if upstream_completed($env);
        sleep 0.1;
    }
    ok upstream_completed($env), "upstream completed sending the response";
};

subtest "end of stream received while buffer is full" => sub {
    my $backend_port = empty_port();
    my $listen = IO::Socket::INET->new(
        LocalHost => "127.0.0.1",
        LocalPort => $backend_port,
        Proto     => "tcp",
        Listen    => 1,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$backend_port:$!";
    my $backend = spawn_forked(sub {
        my $sock = $listen->accept;
        my $req = "";
        while ($req !~ /\r\n\r\n/) {
            $sock->sysread($req, 4096, length $req) or last;
        }
        # send the end of the response separately, so that the upstream would send FIN without data
        $sock->syswrite(sprintf "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n%x\r\n%s\r\n", $small_size, "y" x $small_size);
        sleep 1;
        $sock->syswrite("0\r\n\r\n");
        while ($sock->sysread(my $buf, 4096)) {}
    });
    close $listen;
    my $env = setup("proxy.max-buffer-size: 65536", $backend_port);
    my $req = start_request($env, "/chunked/", "y", 5000);
    my $completed;
    for (1..40) {
        last if $completed = upstream_completed($env);
        sleep 0.1;
    }
    ok $completed, "upstream completed sending the response while the client was stalled";
    test_response($req, $small_size);
};

done_testing;

sub setup {
    my ($proxy_conf, $backend_port) = @_;
    $backend_port ||= empty_port();

    my $upstream_port = empty_port({ host => "127.0.0.1", proto => "udp" });
    my $access_log = "$tempdir/access-log-$upstream_port";
    my $upstream = spawn_h2o_raw(<< "EOT", [{host => "127.0.0.1", port => $upstream_port, proto => "udp"}]);
listen:
  type: quic
  host: 127.0.0.1
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
access-log:
  path: $access_log
  format: "%s %b"
hosts:
  default:
    paths:
      /:
        file.dir: $tempdir
      /chunked:
        proxy.reverse.url: http://127.0.0.1:$backend_port
EOT

    my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.http3.ratio: 100
        $proxy_conf
EOT

    return {
        server     => $server,
        upstream   => $upstream,
        access_log => $access_log,
    };
}

sub upstream_completed {
    my $env = shift;
    open my $fh, "<", $env->{access_log}
        or return 0;
    my @lines = <$fh>;
    return scalar @lines;
}

sub start_request {
    my ($env, $path, $expected_char, $stall_ms) = @_;
    open my $fh, "-|", bindir() . "/h2get_bin/h2get", $scriptfn, "127.0.0.1:$env->{server}->{tls_port}", $path, $expected_char,
        $stall_ms
        or die "failed to spawn h2get:$!";
    while (my $line = <$fh>) {
        last if $line eq "stalled\n";
    }
    return $fh;
}

sub test_response {
    my ($fh, $expected_size) = @_;
    my $output = do { local $/; <$fh> };
    close $fh;
    is $output, "status=200 length=$expected_size content=ok\n", "response";
}
