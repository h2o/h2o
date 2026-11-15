use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Test::More;
use t::Util;

# RFC 9113 Section 5.1: frames received on a stream after sending RST_STREAM are ignored, but header blocks are still decoded to keep
# the header table in sync. The test sends trailers on a stream that has been reset by h2o due to the request body being too large,
# then sends a request that refers to the header table entry inserted by the trailers.

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
limit-request-body: 6
EOT

sub frame {
    my ($type, $flags, $stream_id, $payload) = @_;
    pack("CnCCN", length($payload) >> 16, length($payload) & 0xffff, $type, $flags, $stream_id) . $payload;
}

# reads frames until the callback returns true, returning the frame that matched
sub read_until {
    my ($sock, $input, $cb) = @_;
    while (1) {
        while (length $$input >= 9) {
            my ($len_hi, $len_lo, $type, $flags, $stream_id) = unpack "CnCCN", $$input;
            my $len = ($len_hi << 16) | $len_lo;
            last if length $$input < 9 + $len;
            my $frame = {type => $type, flags => $flags, stream_id => $stream_id, payload => substr $$input, 9, $len};
            $$input = substr $$input, 9 + $len;
            return $frame if $cb->($frame);
        }
        return undef unless IO::Select->new($sock)->can_read(3) && $sock->sysread($$input, 65536, length $$input);
    }
}

for my $continuation (0, 1) {
    subtest $continuation ? "with CONTINUATION" : "without CONTINUATION" => sub {
        my $sock = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$server->{port}",
            Proto    => 'tcp',
        ) or die "failed to connect to 127.0.0.1:$server->{port}:$!";
        my $input = '';

        # send a POST request with a body exceeding the limit, and wait for the stream to be reset
        $sock->syswrite(join "",
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            frame(4, 0, 0, ""),
            frame(1, 0x4, 1, "\x83\x86\x84\x41\x09localhost"),
            frame(0, 0, 1, "helloworld"),
        );
        ok read_until($sock, \$input, sub { $_[0]{type} == 3 && $_[0]{stream_id} == 1 }), "RST_STREAM";

        # send trailers on the closed stream inserting `x: y` into the header table, followed by a request referring to that entry
        $sock->syswrite(join "",
            $continuation
                ? (frame(1, 0x1, 1, "\x40\x01x"), frame(9, 0x4, 1, "\x01y"))
                : frame(1, 0x5, 1, "\x40\x01x\x01y"),
            frame(1, 0x5, 3, "\x82\x86\x84\x01\x09localhost\xbe"),
        );
        my $frame = read_until($sock, \$input, sub { $_[0]{type} == 7 || ($_[0]{type} == 1 && $_[0]{stream_id} == 3) });
        ok $frame && $frame->{type} == 1, "response received"
            or diag $frame ? sprintf("GOAWAY: error code %d, %s", unpack("x4N", $frame->{payload}), substr $frame->{payload}, 8)
                           : "no response";
    };
}

done_testing;
