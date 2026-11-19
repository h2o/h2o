use strict;
use warnings;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

# Tests of the native MoQ listener (`moq` of `listen`) that need no MoQ peer: quicly's cli is the client, and the relay is not
# running, which the handshake with the client does not depend on. The listener serves HTTP/3 as well, picked by the ALPN.

my $cli = bindir() . "/quicly/cli";
plan skip_all => "$cli not found"
    unless -e $cli;
my $httpclient = bindir() . "/h2o-httpclient";
plan skip_all => "$httpclient not found"
    unless -e $httpclient;

my $relay_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $native_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $server = spawn_h2o({
    conf => << "EOT",
http3-graceful-shutdown-timeout: 1
hosts:
  default:
    listen:
      type: quic
      host: 127.0.0.1
      port: $native_port
      moq: moqt://127.0.0.1:$relay_port
      ssl:
        key-file: examples/h2o/server.key
        certificate-file: examples/h2o/server.crt
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT
    extra_ports => { port => $native_port, proto => 'udp' },
});

subtest 'handshake' => sub {
    my $handshake = sub {
        my $opts = shift;
        my $out = `timeout 10 $cli $opts --exit-after-handshake 127.0.0.1 $native_port < /dev/null 2>&1`;
        return ($? >> 8, $out);
    };
    # quicly's cli exits 0 when the server refuses the handshake, too; it prints the TLS alert. With `-E`, the ClientHello spans more
    # than one Initial packet, and the ALPN is known only once the connection has been accepted.
    for my $alpn (qw(moqt-22 h3)) {
        for my $opts ("-a $alpn", "-a $alpn -E") {
            my ($status, $out) = $handshake->($opts);
            ok $status == 0 && $out !~ /TLS alert/, "$opts" or diag $out;
        }
    }
    my ($status, $out) = $handshake->("-a h2");
    like $out, qr/TLS alert:code=120\b/, "no_application_protocol without a MoQ or HTTP/3 ALPN";
};

subtest 'HTTP/3' => sub {
    for my $i (1 .. 2) {
        my $resp = `timeout 10 $httpclient -k -3 100 https://127.0.0.1:$native_port/index.txt 2> /dev/null`;
        is $resp, "hello\n", "request $i";
    }
};

ok kill(0, $server->{pid}), "h2o is running";

done_testing;
