use strict;
use warnings;
use Fcntl qw(SEEK_CUR);
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep time);
use t::RawConnection;
use t::Util;

my $cli = bindir() . "/quicly/cli";
plan skip_all => "$cli not found"
    unless -e $cli;

my $tempdir = tempdir(CLEANUP => 1);
my $quic_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $access_log = "$tempdir/access.log";
my $access_log_fh;

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  quic:
    qpack-decoder-table-capacity: 4096
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
access-log:
  path: $access_log
  format: "%U %{user-agent}i %{http3.qpack-blocked}x"
EOT

subtest "dynamic table" => sub {
    my $conn = new_conn();
    $conn->send(stream_frame(2, h3_control_stream()) . stream_frame(6, h3_qpack_encoder_stream()) .
                stream_frame(0, h3_request_headers(), 1));
    sleep 0.1;
    $conn->send(connection_close_frame());

    is wait_log(), "/qpack-dynamic abcdefghij 0", "dynamic header block decoded without blocking";
};

subtest "dynamic table, blocked" => sub {
    my $conn = new_conn();
    $conn->send(stream_frame(2, h3_control_stream()) . stream_frame(0, h3_request_headers(), 1));

    is wait_log(0.2), undef, "request remains parked while QPACK-blocked";

    $conn->send(stream_frame(6, h3_qpack_encoder_stream()));
    sleep 0.1;
    $conn->send(connection_close_frame());
    is wait_log(), "/qpack-dynamic abcdefghij 1", "blocked dynamic header block is resumed";
};

subtest "dynamic table, connection closed while blocked" => sub {
    my $conn = new_conn();
    $conn->send(stream_frame(2, h3_control_stream()) . stream_frame(0, h3_request_headers(), 1));

    is wait_log(0.2), undef, "request remains parked while QPACK-blocked";

    $conn->send(connection_close_frame());
    is wait_log(0.2), undef, "no log entry for stream destroyed while QPACK-blocked";

    # Subsequent subtest will fail if the server crashed during teardown of the blocked stream.
};

subtest "dynamic table, stream reset while blocked" => sub {
    my $conn = new_conn();
    my $headers = h3_request_headers();
    $conn->send(stream_frame(2, h3_control_stream()) . stream_frame(0, $headers, 1));

    is wait_log(0.2), undef, "request remains parked while QPACK-blocked";

    $conn->send(reset_stream_frame(0, 0, length $headers));
    is wait_log(0.2), undef, "no log entry for reset blocked stream";

    $conn->send(connection_close_frame());
};

done_testing;

sub new_conn {
    t::RawConnection->new("127.0.0.1", $quic_port, cli => $cli, alpn => ["h3"]);
}

sub h3_control_stream {
    return quicint(0) . quicint(4) . quicint(0); # control stream, empty SETTINGS
}

sub h3_qpack_encoder_stream {
    return quicint(2) . pack("H*", "ff20881c6490b2cd39ba7f");
}

sub h3_request_headers {
    my $payload = pack("H*", "0280d1d7500161518b63b5632755a4f550e9313f10");
    return quicint(1) . quicint(length($payload)) . $payload;
}

sub stream_frame {
    my ($stream_id, $data, $fin) = @_;
    return chr(0x08 | 0x02 | ($fin ? 0x01 : 0)) . quicint($stream_id) . quicint(length($data)) . $data;
}

sub connection_close_frame {
    return "\x1c\x00\x00\x00";
}

sub reset_stream_frame {
    my ($stream_id, $err_code, $final_size) = @_;
    return chr(0x04) . quicint($stream_id) . quicint($err_code) . quicint($final_size);
}

sub quicint {
    my ($v) = @_;
    if ($v < 0x40) {
        return pack("C", $v);
    } elsif ($v < 0x4000) {
        return pack("n", 0x4000 | $v);
    } elsif ($v < 0x40000000) {
        return pack("N", 0x80000000 | $v);
    } else {
        die "unexpectedly large QUIC integer:$v";
    }
}

sub wait_log {
    my ($timeout) = @_;
    $timeout //= 5;

    my $end = time() + $timeout;
    while (time() < $end) {
        if (!defined $access_log_fh) {
            open $access_log_fh, "<", $access_log
                or do { sleep 0.05; next; };
        }
        seek $access_log_fh, 0, SEEK_CUR; # clear EOF so newly-appended lines become visible
        while (defined(my $line = <$access_log_fh>)) {
            chomp $line;
            return $line if $line =~ /\S/;
        }
        sleep 0.05;
    }
    return undef;
}
