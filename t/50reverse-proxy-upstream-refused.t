use strict;
use warnings;
use IO::Socket::SSL;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

# HTTP/2 upstream that refuses every request with RST_STREAM(REFUSED_STREAM)
my $upstream_port = empty_port();
my $upstream = IO::Socket::SSL->new(
    LocalAddr          => "127.0.0.1:$upstream_port",
    Listen             => 5,
    ReuseAddr          => 1,
    SSL_cert_file      => "examples/h2o/server.crt",
    SSL_key_file       => "examples/h2o/server.key",
    SSL_alpn_protocols => ['h2'],
) or die "failed to listen:$!:$SSL_ERROR";
my $upstream_guard = spawn_forked(sub {
    sub read_exact {
        my ($sock, $len) = @_;
        my $buf = '';
        while (length($buf) < $len) {
            my $ret = $sock->sysread($buf, $len - length($buf), length($buf));
            return undef unless $ret;
        }
        $buf;
    }
    sub build_frame {
        my ($type, $flags, $stream_id, $payload) = @_;
        substr(pack("N", length $payload), 1) . pack("CCN", $type, $flags, $stream_id) . $payload;
    }
    while (my $sock = $upstream->accept) {
        next unless defined read_exact($sock, 24); # connection preface
        $sock->syswrite(build_frame(4, 0, 0, '')); # SETTINGS
        while (defined(my $header = read_exact($sock, 9))) {
            my ($len_hi, $len_lo, $type, $flags, $stream_id) = unpack("CnCCN", $header);
            last unless defined read_exact($sock, ($len_hi << 16) | $len_lo);
            if ($type == 4 && ($flags & 1) == 0) {
                $sock->syswrite(build_frame(4, 1, 0, '')); # SETTINGS ACK
            } elsif ($type == 1) {
                $sock->syswrite(build_frame(3, 0, $stream_id, pack("N", 7))); # RST_STREAM(REFUSED_STREAM)
            }
        }
        close $sock;
    }
});

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT

subtest "http/1" => sub {
    plan skip_all => "curl not found"
        unless prog_exists("curl");
    # the connection is closed without any response being sent, so that the client can retry
    my $resp = `curl --silent --show-error --max-time 10 http://127.0.0.1:$server->{port}/ 2>&1`;
    like $resp, qr{Empty reply from server}, "connection closed without response";
};

subtest "http/2" => sub {
    plan skip_all => "nghttp not found"
        unless prog_exists("nghttp");
    my $resp = `nghttp -v https://127.0.0.1:$server->{tls_port}/ 2>&1`;
    unlike $resp, qr{recv \(stream_id=\d+\) :status}, "no response";
    like $resp, qr{recv RST_STREAM[^\n]*\n[^\n]*error_code=REFUSED_STREAM}s, "stream is reset with REFUSED_STREAM";
};

subtest "http/3" => sub {
    my $client_prog = bindir() . "/h2o-httpclient";
    plan skip_all => "$client_prog not found"
        unless -e $client_prog;
    # the request is rejected without a response being sent (previously, a HEADERS frame carrying `:status: 0` was sent, which the
    # client rejected as an invalid pseudo header)
    my $resp = `$client_prog -3 100 -k https://127.0.0.1:$server->{quic_port}/ 2>&1`;
    unlike $resp, qr{^HTTP/|invalid pseudo header}m, "no response";
    like $resp, qr{I/O error}, "stream is reset";
};

done_testing;
