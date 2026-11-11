use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Test::More;
use t::Util;

# RFC 9113 Section 6.2: a HEADERS frame without END_HEADERS MUST be followed by a CONTINUATION frame for the same stream; receipt of
# a frame on a different stream is a connection error of type PROTOCOL_ERROR.

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
EOT

sub frame {
    my ($type, $flags, $stream_id, $payload) = @_;
    pack("CnCCN", length($payload) >> 16, length($payload) & 0xffff, $type, $flags, $stream_id) . $payload;
}

my $sock = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$server->{port}",
    Proto    => 'tcp',
) or die "failed to connect to 127.0.0.1:$server->{port}:$!";

$sock->syswrite(join "",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    frame(4, 0, 0, ""),
    # stream 1: POST request with the body yet to be sent; i.e., the stream waits for DATA or trailers
    frame(1, 0x4, 1, "\x83\x86\x84\x41\x09localhost"),
    # stream 3: HEADERS without END_HEADERS, carrying "x-foo: bar"
    frame(1, 0x1, 3, "\x00\x05x-foo\x03bar"),
    # CONTINUATION with END_HEADERS sent on stream 1
    frame(9, 0x4, 1, ""),
);

my $input = '';
my $goaway;
while (!defined $goaway && IO::Select->new($sock)->can_read(3)) {
    last unless $sock->sysread($input, 65536, length $input);
    while (length $input >= 9) {
        my ($len_hi, $len_lo, $type) = unpack "CnC", $input;
        my $len = ($len_hi << 16) | $len_lo;
        last if length $input < 9 + $len;
        $goaway = unpack "x4N", substr $input, 9, $len
            if $type == 7;
        $input = substr $input, 9 + $len;
    }
}
is $goaway, 1, "GOAWAY with PROTOCOL_ERROR";

done_testing;
