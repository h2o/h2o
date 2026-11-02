use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Test::More;
use t::Util;

# RFC 9113 Section 3.4: the client connection preface consists of the 24-octet
# magic followed by a SETTINGS frame, which MUST be the first frame the client
# sends. A different first frame is a connection error of type PROTOCOL_ERROR.

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

sub read_all {
    my ($sock) = @_;
    my $input = '';
    while (IO::Select->new($sock)->can_read(3)) {
        last unless $sock->sysread($input, 65536, length $input);
    }
    $input;
}

sub first_goaway {
    my ($bytes) = @_;
    while (length $bytes >= 9) {
        my ($len_hi, $len_lo, $type) = unpack "CnC", $bytes;
        my $len = ($len_hi << 16) | $len_lo;
        last if length $bytes < 9 + $len;
        return unpack "x4N", substr $bytes, 9, $len
            if $type == 7;
        $bytes = substr $bytes, 9 + $len;
    }
    undef;
}

sub saw_response_headers {
    my ($bytes) = @_;
    while (length $bytes >= 9) {
        my ($len_hi, $len_lo, $type) = unpack "CnC", $bytes;
        my $len = ($len_hi << 16) | $len_lo;
        my $sid = unpack "N", substr $bytes, 5, 4;
        last if length $bytes < 9 + $len;
        return 1 if $type == 1 && ($sid & 0x7fffffff) == 1;
        $bytes = substr $bytes, 9 + $len;
    }
    0;
}

# first frame is HEADERS (no SETTINGS): must be rejected
my $sock = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$server->{port}",
    Proto    => 'tcp',
) or die "failed to connect to 127.0.0.1:$server->{port}:$!";

$sock->syswrite(join "",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    frame(1, 0x5, 1, "\x82\x84\x87\x41\x09localhost"),
);
my $bad = read_all($sock);
close($sock);
is first_goaway($bad), 1, "GOAWAY with PROTOCOL_ERROR when first frame is not SETTINGS";
ok !saw_response_headers($bad), "request not processed";

# first frame is SETTINGS: must work
my $sock2 = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$server->{port}",
    Proto    => 'tcp',
) or die "failed to connect to 127.0.0.1:$server->{port}:$!";

$sock2->syswrite(join "",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    frame(4, 0, 0, ""),
    frame(1, 0x5, 1, "\x82\x84\x87\x41\x09localhost"),
);
my $good = read_all($sock2);
close($sock2);
ok saw_response_headers($good), "response received when SETTINGS is sent first";
ok !defined first_goaway($good), "no GOAWAY";

done_testing;
