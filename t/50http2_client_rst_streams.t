use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use File::Temp qw(tempfile tempdir);
use Net::EmptyPort qw(check_port wait_port);
use JSON;
use Fcntl qw(F_SETFD);
use IO::Select;

plan skip_all => "ss not found"
    unless prog_exists("ss");

sub dotest {
    my $code = shift;
    my $testfn = shift;
    my $h2g = spawn_h2get_backend($code);

    my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 20
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
        proxy.http2.force-cleartext: OFF
        proxy.timeout.keepalive: 100000
EOT

    wait_port($h2g->{tls_port});

    my ($stdout, $stderr) = run_with_h2get_simple($server, <<"EOR");
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/",
    }

    h2g.send_headers(req, 1, END_HEADERS | END_STREAM)
    sleep(1)
    h2g.send_rst_stream(1, 0x8)
    h2g.read(1000)
    puts("h2get client exiting")
EOR

    is $stderr, "h2get client exiting\n", "h2 client finished as expected";

    sleep 2;
    my ($out, $err) = $h2g->{kill}->();
    $testfn->($err, $out);
}

subtest "late headers frame", sub {
    dotest(<< "EOC"
    puts f.type
    conn.send_headers({":status" => "200"}, f.stream_id, END_HEADERS | END_STREAM) if f.type == 'RST_STREAM'
EOC
    , sub {
        my ($err, $out) = @_;
        ok !$err, "no error from h2 backend";
        if ($err) {
            diag($err);
        }
        is $out, "HEADERS\nSETTINGS\nRST_STREAM\n", "no GOAWAY frame seen";
    });
};

subtest "late data frame", sub {
    dotest(<< "EOC"
    puts f.type
    conn.send_headers({":status" => "200"}, f.stream_id, END_HEADERS) if f.type == 'HEADERS'
    conn.send_data(f.stream_id, 0, 'racy DATA frame') if f.type == 'RST_STREAM'
EOC
    , sub {
        my ($err, $out) = @_;
        ok !$err, "no error from h2 backend";
        if ($err) {
            diag($err);
        }
        is $out, "HEADERS\nSETTINGS\nRST_STREAM\nWINDOW_UPDATE\n", "no GOAWAY frame seen, WINDOW_UPDATE seen";
    });
};

subtest "late trailers on a cancelled stream do not abort another stream", sub {
    plan skip_all => "h2get not found"
        unless h2get_exists();

    pipe my $done_r, my $done_w or die "pipe failed:$!";
    # Let the backend notify us through this pipe after exec.
    fcntl($done_w, F_SETFD, 0) or die "fcntl failed:$!";
    my $done_fd = fileno($done_w);
    my $h2g = spawn_h2get_backend(<< "EOC");
    # Keep IDs per connection: the DATA marker below proves multiplexing.
    if f.type == 'HEADERS'
        if connpool[conn] == true
            connpool[conn] = [f.stream_id]
            conn.send_headers({":status" => "200"}, f.stream_id, END_HEADERS)
        else
            connpool[conn] << f.stream_id
            puts "two requests on one connection"
            conn.send_data(connpool[conn][0], 0, "both requests received")
        end
    elsif f.type == 'RST_STREAM'
        raise "unexpected reset" unless f.stream_id == connpool[conn][0]
        puts "RST_STREAM #{f.stream_id}: #{f.to_a.join(',')}"
        conn.send_headers({"x-checksum" => "1"}, f.stream_id, END_HEADERS | END_STREAM)
        puts "sent late trailer"
        # The ACK proves H2O processed the preceding trailer before we
        # complete the other response, without a timing assumption.
        conn.send_ping()
    elsif f.type == 'PING' && f.flags == ACK
        puts "trailer processed"
        conn.send_headers({":status" => "200", "content-length" => "4"}, connpool[conn][1], END_HEADERS)
        conn.send_data(connpool[conn][1], END_STREAM, "B-OK")
        done = IO.new($done_fd, "w")
        done.write("1")
        done.close
    elsif f.type == 'GOAWAY'
        puts f.to_s
        done = IO.new($done_fd, "w")
        done.write("1")
        done.close
    end
EOC
    close $done_w;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT

    my ($stderr, $stdout) = run_with_h2get_simple($server, <<'EOR');
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/",
    }
    h2g.send_headers(req, 1, END_HEADERS | END_STREAM)
    loop do
        f = h2g.read(5000)
        raise "no first response headers" if f.nil?
        break if f.type == 'HEADERS' && f.stream_id == 1
    end
    h2g.send_headers(req, 3, END_HEADERS | END_STREAM)
    loop do
        f = h2g.read(5000)
        raise "requests did not share an upstream connection" if f.nil?
        break if f.type == 'DATA' && f.stream_id == 1 && f.payload == "both requests received"
    end
    puts "both requests received"
    h2g.send_rst_stream(1, 0x8)
    body = ""
    loop do
        f = h2g.read(5000)
        raise "second response timed out" if f.nil?
        raise "downstream connection failed: #{f.to_s}" if f.type == 'GOAWAY'
        next unless f.stream_id == 3
        puts f.to_s if f.type == 'HEADERS' || f.type == 'RST_STREAM'
        body += f.payload if f.type == 'DATA'
        break if f.is_end_stream || f.type == 'RST_STREAM'
    end
    puts "body: #{body}"
EOR

    is $stderr, "", "no error from h2 client";
    like $stdout, qr/^both requests received$/m, "both requests reached the same upstream connection";
    like $stdout, qr/':status' => '200'/, "second response has status 200";
    like $stdout, qr/^body: B-OK$/m, "second response completes successfully";

    # Synchronize with the backend before collecting its output. This also
    # bounds the wait if a setup error prevents reaching the trailer exchange.
    my $completed = IO::Select->new($done_r)->can_read(5) && sysread($done_r, my $done, 1);
    ok $completed, "backend finished processing the trailer";
    close $done_r;
    my ($out, $err) = $h2g->{kill}->();
    is $err, "", "no error from h2 backend";
    like $out, qr/^two requests on one connection$/m, "upstream observed both streams";
    like $out, qr/^RST_STREAM \d+: 0,0,0,8$/m, "upstream observed cancellation before sending the trailer";
    like $out, qr/^sent late trailer$/m, "upstream sent a trailer without :status";
    unlike $out, qr/GOAWAY/, "no connection error for the late trailer";
    like $out, qr/^trailer processed$/m, "connection remains usable after the trailer";
    diag $out if $out =~ /GOAWAY/;
};

done_testing();
