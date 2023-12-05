use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use File::Temp qw(tempfile tempdir);
use Net::EmptyPort qw(check_port wait_port);
use JSON;

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

done_testing();
