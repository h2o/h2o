use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(time);
use t::RawConnection;
use t::Util;

# A request that does not carry a content-length header is not bounded by it: the size of the body
# is bounded by the limit that applies to the request entity, as it is in HTTP/2. Verify that a
# request whose body exceeds the limit is rejected (VULN-005). The proxy is used as the handler, as
# it is the handler that reads the body of the request before responding; the file handler responds
# immediately and the stream leaves the state that receives the body before the DATA frames arrive.

my $cli = bindir() . "/quicly/cli";
plan skip_all => "$cli not found"
    unless -e $cli;

# create a socket to keep an empty port in use; the upstream accepts connections but never responds,
# so that the proxy parks the stream in the state that receives the body
my $upstream = IO::Socket::INET->new(
    LocalAddr => "127.0.0.1",
    LocalPort => 0,
    Proto     => "tcp",
) or die "failed to open socket:$!";
my $upstream_port = $upstream->sockport;

my $server = spawn_h2o(<< "EOT");
limit-request-body: 4096
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.timeout.io: 30000
EOT

sub quicint {
    my ($v) = @_;
    if ($v < 0x40) {
        return pack("C", $v);
    } elsif ($v < 0x4000) {
        return pack("n", 0x4000 | $v);
    } else {
        die "unexpectedly large QUIC integer:$v";
    }
}

sub h3_frame {
    my ($type, $payload) = @_;
    return quicint($type) . quicint(length($payload)) . $payload;
}

sub stream_frame {
    my ($stream_id, $data, $fin) = @_;
    return chr(0x08 | 0x02 | ($fin ? 0x01 : 0)) . quicint($stream_id) . quicint(length($data)) . $data;
}

sub h3_control_stream {
    return quicint(0) . quicint(4) . quicint(0); # control stream, empty SETTINGS
}

sub h3_qpack_encoder_stream {
    return quicint(2) . pack("H*", "ff20881c6490b2cd39ba7f");
}

# a HEADERS frame that carries a POST request for /qpack-dynamic; the request does not carry a
# content-length header. The QPACK-encoded field section is derived from the one that the test of
# the QPACK dynamic table uses, with the method changed from GET (static index 17, encoded as 0xd1)
# to POST (static index 20, encoded as 0xd4), so that the server parks the stream in the state that
# receives the body
sub h3_request_headers {
    my $payload = pack("H*", "0280d4d7500161518b63b5632755a4f550e9313f10");
    return h3_frame(1, $payload);
}

subtest "request body without content-length exceeding the limit is rejected" => sub {
    my $conn = t::RawConnection->new("127.0.0.1", $server->{quic_port}, cli => $cli, alpn => ["h3"]);

    # the setup and the HEADERS frame fit in one packet
    $conn->send(stream_frame(2, h3_control_stream()) . stream_frame(6, h3_qpack_encoder_stream()) .
                stream_frame(0, h3_request_headers()));
    # the DATA frames are sent one per packet, as a QUIC packet carries at most ~1400 bytes of payload
    for my $i (1 .. 5) {
        $conn->send(stream_frame(0, h3_frame(0, "X" x 1024))); # 5 * 1024 = 5120 > 4096
    }

    ok wait_request_rejected($conn), "the server rejects the stream whose body exceeds the limit";
};

done_testing;

# waits until the server sends a STOP_SENDING or a RESET_STREAM that carries the error code
# H3_REQUEST_REJECTED (0x010b), which the server sends when the body of a request exceeds the limit
sub wait_request_rejected {
    my $conn = shift;
    my $select = IO::Select->new($conn->{sock});
    my $deadline = time + 10;
    while ((my $timeout = $deadline - time) > 0) {
        return 0
            unless $select->can_read($timeout);
        my $packet = $conn->receive;
        next unless defined $packet;
        # H3_REQUEST_REJECTED (0x10b) as a QUIC varint is \x41\x0b; the server sends it inside a
        # STOP_SENDING (type 0x03) or a RESET_STREAM (type 0x04) frame for the request stream (0)
        return 1
            if $packet =~ /\x03\x00\x41\x0b/ || $packet =~ /\x04\x00\x41\x0b/;
    }
    return 0;
}