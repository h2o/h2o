use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

my $tempdir = tempdir(CLEANUP => 1);
{
    open my $fh, ">", "$tempdir/body" or die "failed to create file:$!";
    print $fh "x" x 1000000;
}

# Each upstream stops sending after the frames listed. The PING frames make h2o write (PING ACK) after reading the response
# frames, as is the case when a write happens for any other reason.
subtest "incomplete header block" => sub {
    # PING is sent before HEADERS, as no frame other than CONTINUATION can follow; both are expected to be read at once
    doit(<< "EOC", "");
    if f.type == 'HEADERS' then
        conn.send_ping()
        conn.send_headers({":status" => "200"}, f.stream_id, 0)
    end
EOC
};

subtest "response headers" => sub {
    doit(<< "EOC", "");
    if f.type == 'HEADERS' then
        conn.send_headers({":status" => "200", "content-length" => "10"}, f.stream_id, END_HEADERS)
        conn.send_ping()
    end
EOC
};

subtest "response headers and partial body" => sub {
    doit(<< "EOC", "");
    if f.type == 'HEADERS' then
        conn.send_headers({":status" => "200", "content-length" => "10"}, f.stream_id, END_HEADERS)
        conn.send_data(f.stream_id, 0, "hello")
        conn.send_ping()
    end
EOC
};

subtest "request body blocked by flow control" => sub {
    # the upstream never sends WINDOW_UPDATE
    doit("conn.send_ping() if f.type == 'DATA'", "--data-binary \@$tempdir/body");
};

subtest "stalled stream while another stream receives data" => sub {
    # stream 1 receives response headers then nothing, while stream 3 receives a byte every second for 6 seconds
    my $h2g = spawn_h2get_backend(<< "EOC");
    if f.type == 'HEADERS' then
        if f.stream_id == 1 then
            conn.send_headers({":status" => "200", "content-length" => "10"}, f.stream_id, END_HEADERS)
        else
            conn.send_headers({":status" => "200", "content-length" => "6"}, f.stream_id, END_HEADERS)
            6.times do |i|
                sleep 1
                conn.send_data(f.stream_id, i == 5 ? END_STREAM : 0, "x")
            end
        end
    end
EOC
    my $server = spawn_h2o_with_backend($h2g, "proxy.timeout.io: 2000");
    my $start_at = time;
    open my $stalled, "-|", "curl --silent --show-error --max-time 15 http://127.0.0.1:$server->{port}/ 2>&1"
        or die "failed to spawn curl:$!";
    Time::HiRes::sleep(0.5);
    open my $active, "-|", "curl --silent --show-error --max-time 15 http://127.0.0.1:$server->{port}/ 2>&1"
        or die "failed to spawn curl:$!";
    my $stalled_resp = do { local $/; <$stalled> };
    my $elapsed = time - $start_at;
    unlike $stalled_resp, qr/Operation timed out/, "timed out by h2o";
    # the stalled stream is expected to be timed out at 2 seconds, while the other stream runs until 6.5 seconds
    cmp_ok $elapsed, "<", 4, "stalled stream is timed out";
    is do { local $/; <$active> }, "xxxxxx", "the stream receiving data is not affected";
    $h2g->{kill}->();
};

subtest "first byte timeout longer than I/O timeout" => sub {
    # While the response is awaited, the upstream sends a frame to which h2o does not respond, as is the case with SETTINGS ACK
    # on a fresh connection.
    my $h2g = spawn_h2get_backend(<< "EOC");
    if f.type == 'HEADERS' then
        sleep 1
        conn.send_window_update(0, 1)
        sleep 2
        conn.send_headers({":status" => "200", "content-length" => "5"}, f.stream_id, END_HEADERS)
        conn.send_data(f.stream_id, END_STREAM, "hello")
    end
EOC
    my $server = spawn_h2o_with_backend($h2g, "proxy.timeout.io: 1000\n        proxy.timeout.first_byte: 5000");
    my $resp = `curl --silent --show-error --max-time 10 http://127.0.0.1:$server->{port}/ 2>&1`;
    is $resp, "hello", "response is received";
    $h2g->{kill}->();
};

done_testing();

sub spawn_h2o_with_backend {
    my ($h2g, $timeouts) = @_;
    # one thread, so that the requests would share one upstream connection
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
        $timeouts
EOT
    wait_port($h2g->{tls_port});
    $server;
}

sub doit {
    my ($snippet, $curl_opts) = @_;
    my $h2g = spawn_h2get_backend($snippet);
    my $server = spawn_h2o_with_backend($h2g, "proxy.timeout.io: 1000");
    my $start_at = time;
    my $resp = `curl --silent --show-error --max-time 10 $curl_opts http://127.0.0.1:$server->{port}/ 2>&1`;
    my $elapsed = time - $start_at;
    unlike $resp, qr/Operation timed out/, "timed out by h2o";
    cmp_ok $elapsed, '<', 3, "upstream is timed out promptly";
    $h2g->{kill}->();
}
