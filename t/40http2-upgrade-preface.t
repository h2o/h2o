use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Test::More;
use t::Util;

# Tests that the server connection preface (SETTINGS and the connection-level WINDOW_UPDATE) is sent only once when upgrading
# from HTTP/1.1 to HTTP/2 (h2c).

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

my $sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$server->{port}")
    or die "failed to connect to 127.0.0.1:$server->{port}:$!";
syswrite $sock, join "",
    "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: Upgrade, HTTP2-Settings\r\nupgrade: h2c\r\nhttp2-settings: \r\n\r\n",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    pack("NCN", 0 << 8 | 4, 0, 0); # empty SETTINGS frame

my $resp = "";
my $select = IO::Select->new($sock);
while ($select->can_read(1)) {
    sysread($sock, my $buf, 65536)
        or last;
    $resp .= $buf;
}
like $resp, qr{^HTTP/1\.1 101 }s, "101 response";
my $off = index($resp, "\r\n\r\n") + 4;

my ($num_settings, $num_conn_window_updates) = (0, 0);
while ($off + 9 <= length $resp) {
    my ($len_type, $flags, $stream_id) = unpack "NCN", substr $resp, $off, 9;
    my ($len, $type) = ($len_type >> 8, $len_type & 0xff);
    ++$num_settings if $type == 4 && ($flags & 1) == 0;
    ++$num_conn_window_updates if $type == 8 && $stream_id == 0;
    $off += 9 + $len;
}
is $num_settings, 1, "one SETTINGS frame";
is $num_conn_window_updates, 1, "one connection-level WINDOW_UPDATE frame";

done_testing();
