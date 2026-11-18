use strict;
use warnings;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

# Tests of the native MoQ listener (`moq` of `listen`) that need no MoQ peer: quicly's cli is the client, and the relay is not
# running, which the handshake with the client does not depend on.

my $cli = bindir() . "/quicly/cli";
plan skip_all => "$cli not found"
    unless -e $cli;

subtest 'handshake' => sub {
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

    my $handshake = sub {
        my $alpn = shift;
        my $out = `timeout 10 $cli -a $alpn --exit-after-handshake 127.0.0.1 $native_port < /dev/null 2>&1`;
        return ($? >> 8, $out);
    };

    # quicly's cli exits 0 when the server refuses the handshake, too; it prints the TLS alert
    for my $i (1 .. 2) {
        my ($status, $out) = $handshake->("moqt-22");
        ok $status == 0 && $out !~ /TLS alert/, "handshake $i with moqt-22" or diag $out;
    }
    my ($status, $out) = $handshake->("h3");
    like $out, qr/TLS alert:code=120\b/, "no_application_protocol without a MoQ ALPN";
    ok kill(0, $server->{pid}), "h2o is running";
};

done_testing;
