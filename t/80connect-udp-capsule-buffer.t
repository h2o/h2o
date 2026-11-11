use strict;
use warnings;
use Errno qw(EAGAIN ECONNRESET EWOULDBLOCK);
use File::Temp qw(tempdir);
use IO::Handle;
use IO::Select;
use IO::Socket::INET;
use Path::Tiny;
use Test::More;
use Time::HiRes qw(sleep time);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $max_capsule_value_size = 8 + 65527;

my $udp_sock = IO::Socket::INET->new(
    LocalHost => "127.0.0.1",
    LocalPort => 0,
    Proto     => "udp",
) or die "failed to open UDP socket:$!";
$udp_sock->blocking(0);
my $udp_port = $udp_sock->sockport;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/rfc9298":
        proxy.connect-udp:
          - "+127.0.0.1:$udp_port"
proxy.timeout.io: 10000
EOT

for my $proto (
    ["h1", "-2 0 -m GET http://127.0.0.1:$server->{port}", qr{^HTTP/1\.1 101}m],
    ["h2", "-2 100 -m CONNECT https://127.0.0.1:$server->{tls_port}", qr{^HTTP/2 200}m],
    ["h3", "-3 100 -m CONNECT https://127.0.0.1:$server->{quic_port}", qr{^HTTP/3 200}m],
) {
    my ($name, $args_url_prefix, $established_re) = @$proto;
    subtest $name => sub {
        my $cmd = "$client_prog --upgrade connect-udp -k $args_url_prefix/rfc9298/127.0.0.1/$udp_port/";

        my $start = time;
        open my $fh, "|-", "exec $cmd > $tempdir/out 2>&1"
            or die "spawn error ($?) for command: $cmd";
        sleep 0.5;
        local $SIG{PIPE} = sub {};
        print $fh oversized_unknown_capsule() . udp_datagram_capsule();
        $fh->flush;
        close $fh;

        ok time - $start < 5, "connection closed before idle timeout";
        like path("$tempdir/out")->slurp, $established_re, "tunnel gets established";
        ok !udp_origin_received(), "$name: UDP datagram does not reach origin";
    };
}

subtest "h1 early data" => sub {
    # H1 can deliver tunnel bytes already read with the request headers through req.entity when udp_connect invokes write_req
    # directly. H2 and H3 enter the handler from CONNECT headers with an empty req.entity; any DATA frames are held by the protocol
    # layer until the handler calls proceed_req after the UDP socket is connected, so their parse failures use the normal streaming
    # write_req path covered above.
    my $sock = IO::Socket::INET->new(
        PeerHost => "127.0.0.1",
        PeerPort => $server->{port},
        Proto    => "tcp",
    ) or die "failed to connect to h2o:$!";
    $sock->autoflush(1);
    print $sock join("\r\n",
        "GET /rfc9298/127.0.0.1/$udp_port/ HTTP/1.1",
        "Host: 127.0.0.1:$server->{port}",
        "Connection: upgrade",
        "Upgrade: connect-udp",
        "",
        "") . oversized_unknown_capsule() . udp_datagram_capsule();

    my $start = time;
    my $deadline = $start + 5;
    my $closed = 0;
    my $output = "";
    my $select = IO::Select->new($sock);
    while (time < $deadline) {
        if ($select->can_read(0.1)) {
            my $buf;
            my $read = sysread($sock, $buf, 65536);
            if (!defined($read)) {
                if ($! == ECONNRESET) {
                    $closed = 1;
                    last;
                }
                die "failed to read from h2o:$!";
            }
            if ($read == 0) {
                $closed = 1;
                last;
            }
            $output .= $buf;
        }
    }
    close $sock;

    ok $closed, "connection closed before idle timeout";
    ok time - $start < 5, "connection closed promptly";
    like $output, qr{^HTTP/1\.1 101}m, "tunnel gets established";
    ok !udp_origin_received(), "h1 early data: UDP datagram does not reach origin";
};

done_testing;

sub udp_origin_received {
    my $datagram;
    if ($udp_sock->recv($datagram, 65535)) {
        return 1;
    }
    return 0
        if $! == EAGAIN || $! == EWOULDBLOCK;
    die "failed to read from UDP origin:$!";
}

sub oversized_unknown_capsule {
    my $unknown_capsule_type = chr(0x21);
    my $length = pack("N", 0x80000000 | ($max_capsule_value_size + 1));
    return $unknown_capsule_type . $length . ("\0" x ($max_capsule_value_size + 1));
}

sub udp_datagram_capsule { return "\0\2\0x" }
