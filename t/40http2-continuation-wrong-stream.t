use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use t::Util;

# RFC 7540 section 6.10 requires the CONTINUATION frames that carry a header block to be sent on the
# stream that the HEADERS frame was sent on; a frame on any other stream is a connection error of
# type PROTOCOL_ERROR. Verify that the server tears the connection down with GOAWAY(PROTOCOL_ERROR)
# when a CONTINUATION frame arrives on a stream that does not own the open header block.

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

sub h2_frame {
    my ($type, $flags, $stream_id, $payload) = @_;
    return substr(pack("N", length($payload)), 1, 3) . pack("CCN", $type, $flags, $stream_id) . $payload;
}

sub send_preface {
    my ($sock) = @_;
    print $sock "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    print $sock h2_frame(0x04, 0, 0, ""); # empty SETTINGS
}

sub read_frame {
    my ($sock) = @_;
    my $buf = "";
    # read the 9-byte frame header
    while (length($buf) < 9) {
        my $b;
        my $n = $sock->sysread($b, 9 - length($buf));
        return undef unless defined $n && $n > 0;
        $buf .= $b;
    }
    my $len = unpack("N", "\x00" . substr($buf, 0, 3));
    my ($type, $flags, $stream_id) = unpack("CCN", substr($buf, 3, 6));
    my $payload = "";
    while (length($payload) < $len) {
        my $b;
        my $n = $sock->sysread($b, $len - length($payload));
        return undef unless defined $n && $n > 0;
        $payload .= $b;
    }
    return ($type, $flags, $stream_id, $payload);
}

subtest "continuation on wrong stream is a protocol error" => sub {
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => $server->{port},
        Proto    => "tcp",
    ) or die "failed to connect to the server:$!";
    $sock->autoflush(1);

    send_preface($sock);

    # a HEADERS frame on stream 1 without END_HEADERS: opens a header block on stream 1
    # the HPACK payload is a static-table indexed header field, index 28 (content-length: 0)
    print $sock h2_frame(0x01, 0, 1, "\x9c");

    # a CONTINUATION frame on stream 3: must be rejected
    print $sock h2_frame(0x09, 0, 3, "\x00");

    # the server sends its own SETTINGS (and its acknowledgement of ours) before the GOAWAY;
    # skip the frames that are not a GOAWAY
    my ($goaway_payload, $error_code);
    while (1) {
        my @frame = read_frame($sock);
        last unless defined $frame[0];
        next unless $frame[0] == 0x07; # GOAWAY
        $goaway_payload = $frame[3];
        $error_code = unpack("N", substr($goaway_payload, 4, 4));
        last;
    }

    ok(defined $error_code, "a GOAWAY is received");
    is($error_code, 0x00000001, "the error code is PROTOCOL_ERROR") if defined $error_code;

    close $sock;
};

done_testing();
