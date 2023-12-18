use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port wait_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

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
        proxy.connect:     # classic CONNECT incl. CONNECT-UDP
          - "+*"
      "/rfc9298":
        proxy.connect-udp: # RFC9298
          - "+*"
proxy.timeout.io: 30000
proxy.connect.masque-draft-03: ON
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
        doit($name, $cmd, 200, sub {
            my $payload = shift;
            "\0". chr(length $payload) . $payload; # only supports payload up to 63 bytes
        });
    }
};

subtest "udp-rfc9298" => sub {
    for (
        ["h1", "-2 0 -m GET http://127.0.0.1:@{[$tunnel_server->{port}]}", 101],
        ["h1s", "-2 0 -m GET https://127.0.0.1:@{[$tunnel_server->{tls_port}]}", 101],
        ["h2", "-2 100 -m CONNECT https://127.0.0.1:@{[$tunnel_server->{tls_port}]}", 200],
        ["h3", "-3 100 -m CONNECT https://127.0.0.1:@{[$tunnel_server->{quic_port}]}", 200],
    ) {
        my ($name, $args_url_prefix, $status_expected) = @$_;
        my $cmd = "$client_prog -k -X $tunnel_port $args_url_prefix/rfc9298/127.0.0.1/@{[$udp_server->{port}]}/";
        doit($name, $cmd, $status_expected, sub {
            my $payload = shift;
            "\0" . chr(1 + length $payload) . "\0" . $payload; # only supports payload up to 63 bytes
        });
    }
};

sub doit {
    my ($name, $cmd, $status_expected, $to_capsule) = @_;

    subtest $name => sub {
        open my $client, "|-", "$cmd > $tempdir/out 2>&1"
            or die "spawn error ($?) for command: $cmd";
        sleep 0.5;

        local $SIG{PIPE} = sub {}; # $client may exit early but we do not want to get killed by SIGPIPE when writing to it

        if ($name eq 'h3') {
            # H3: test exchange using the UDP socket
            for my $mess ("hello", "world") {
                open my $fh, '-|', "echo $mess | nc -u -w 1 127.0.0.1 $tunnel_port"
                    or die "failed to spawn nc:$?";
                my $resp = do {
                    local $/;
                    <$fh>;
                };
                is $resp, "$mess\n", "got UDP echo";
            }
        } else {
            # H1,H2: write from both stdin and UDP socket, but all the responses are sent to the stream
            print $client $to_capsule->("hello");
            print $client $to_capsule->("world");
            flush $client;
            sleep 0.5;
            undef $client;
            my $resp = do {
                open my $fh, "<", "$tempdir/out"
                    or die "failed to open file:$tempdir/out:$!";
                local $/;
                <$fh>;
            };
            my $resp_expected = $to_capsule->("hello") . $to_capsule->("world");
            like $resp, qr{^HTTP/[0-9.]+ $status_expected.*\n\n$resp_expected$}s, "got capsule echos";
        }
    };
}

done_testing;
