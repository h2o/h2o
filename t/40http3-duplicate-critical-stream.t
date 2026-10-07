use strict;
use warnings;
use IO::Select;
use Test::More;
use Time::HiRes qw(time);
use t::RawConnection;
use t::Util;

# Only one control, encoder, and decoder stream is permitted per peer; receipt of a second one is a connection error of type
# H3_STREAM_CREATION_ERROR (RFC 9114 Section 6.2.1, RFC 9204 Section 4.2).

my $cli = bindir() . "/quicly/cli";
plan skip_all => "$cli not found"
    unless -e $cli;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

for my $test ([control => 0], [encoder => 2], [decoder => 3]) {
    my ($name, $type) = @$test;
    subtest $name => sub {
        my $conn = t::RawConnection->new("127.0.0.1", $server->{quic_port}, cli => $cli, alpn => ["h3"]);
        my $streams = stream_frame(2, quicint(0) . quicint(4) . quicint(0)); # control stream, empty SETTINGS
        $streams .= stream_frame(6, quicint($type))
            if $type != 0;
        $streams .= stream_frame(10, quicint($type));
        $conn->send($streams);
        ok wait_stream_creation_error($conn), "connection closed with H3_STREAM_CREATION_ERROR";
    };
}

done_testing;

sub stream_frame {
    my ($stream_id, $data) = @_;
    return chr(0x08 | 0x02) . quicint($stream_id) . quicint(length($data)) . $data;
}

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

# returns if an application CONNECTION_CLOSE frame carrying H3_STREAM_CREATION_ERROR (0x103) is received
sub wait_stream_creation_error {
    my $conn = shift;
    my $select = IO::Select->new($conn->{sock});
    my $deadline = time + 5;
    while ((my $timeout = $deadline - time) > 0) {
        return 0
            unless $select->can_read($timeout);
        my $packet = $conn->receive;
        return 1
            if defined $packet && $packet =~ /\x1d\x41\x03/;
    }
    return 0;
}
