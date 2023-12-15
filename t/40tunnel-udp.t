use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

# setup UDP server to which the client would talk to
my $udp_server = do {
    my $quic_port = empty_port({
        host  => "127.0.0.1",
        proto => "udp",
    });
    my $udp_server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
    wait_port({port => $quic_port, proto => 'udp'});
    $udp_server->{quic_port} = $quic_port;
    $udp_server;
};

# setup H2O that acts as a UDP tunnel
my $tunnel_server = do {
    my $quic_port = empty_port({
        host  => "127.0.0.1",
        proto => "udp",
    });
    my $tunnel_server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+*"
        proxy.timeout.io: 30000
    access-log: /dev/stdout
EOT
    wait_port({port => $quic_port, proto => 'udp'});
    $tunnel_server->{quic_port} = $quic_port;
    $tunnel_server;
};

# determine UDP port to be used by h2o-httpclient
my $tunnel_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

subtest "udp-draft03" => sub {
    my $tunnel = create_tunnel("3", "--connect-udp-draft03");
    foreach my $i (1..5) {
        test_udp_exchange();
    }
};

subtest "udp-rfc9298" => sub {
    my $tunnel = create_tunnel("3", "");
    foreach my $i (1..5) {
        test_udp_exchange();
    }
};

# TODO cover proxying of CONNECT-UDP over HTTP2 (create_tunnel with HTTP2 as first argument)

sub create_tunnel {
    my ($proto, $extra_args) = @_;
    spawn_forked(sub {
        exec "$client_prog -k -$proto 100 $extra_args -X $tunnel_port -x https://127.0.0.1:@{[$tunnel_server->{quic_port}]} 127.0.0.1:@{[$udp_server->{quic_port}]}"
            or die "failed to exec:$?";
    });
}

sub test_udp_exchange {
    my $resp = `$client_prog -o /dev/null -3 100 https://127.0.0.1:$tunnel_port/echo-query 2>&1`;
    like $resp, qr{^HTTP/3 200}s, "200 response";
}

done_testing;
