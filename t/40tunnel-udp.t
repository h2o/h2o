use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port wait_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

# setup UDP echo server to which the client would talk to
my $udp_server = do {
    my $sock = IO::Socket::INET->new(
        LocalHost => "127.0.0.1",
        LocalPort => 0,
        Proto     => "udp",
    ) or die "failed to open UDP socket:$!";
    my $guard = spawn_forked(sub {
        while (my $peer = $sock->recv(my $datagram, 1500)) {
            $sock->send($datagram, 0, $peer);
        }
    });
    $guard->{port} = $sock->sockport;
    $guard;
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
    for (
        ["h1", "-2 0 -x http://127.0.0.1:@{[$tunnel_server->{port}]}"],
        ["h1s", "-2 0 -x https://127.0.0.1:@{[$tunnel_server->{tls_port}]}"],
        ["h2", "-2 100 -x https://127.0.0.1:@{[$tunnel_server->{tls_port}]}"],
        ["h3", "-3 100 -x https://127.0.0.1:@{[$tunnel_server->{quic_port}]}"],
    ) {
        my ($name, $args) = @$_;
        my $cmd = "$client_prog -k -m CONNECT-UDP -X $tunnel_port $args 127.0.0.1:@{[$udp_server->{port}]}";
        doit($name, $cmd);
    }
};

subtest "udp-rfc9298" => sub {
    for (
        ["h1", "-2 0 -m GET http://127.0.0.1:@{[$tunnel_server->{port}]}"],
        ["h1s", "-2 0 -m GET https://127.0.0.1:@{[$tunnel_server->{tls_port}]}"],
        ["h2", "-2 100 -m CONNECT https://127.0.0.1:@{[$tunnel_server->{tls_port}]}"],
        ["h3", "-3 100 -m CONNECT https://127.0.0.1:@{[$tunnel_server->{quic_port}]}"],
    ) {
        my ($name, $args_url_prefix) = @$_;
        my $cmd = "$client_prog -k -X $tunnel_port $args_url_prefix/.well-known/masque/udp/127.0.0.1/@{[$udp_server->{port}]}/";
        doit($name, $cmd);
    }
};

sub doit {
    my ($name, $cmd) = @_;

    subtest $name => sub {
        my $tunnel = spawn_forked(sub {
            exec $cmd or die "got spawn error ($?) for command: $cmd";
        });
        sleep 0.5;
        for (1..5) {
            my $mess = "" . int(100000 * rand);
            open my $fh, '-|', "echo $mess | nc -u -w 1 127.0.0.1 $tunnel_port"
            or die "failed to spawn nc:$?";
            my $resp = do {
                local $/;
                <$fh>;
            };
            is $resp, "$mess\n", "got UDP echo";
        }
    };
}

done_testing;
