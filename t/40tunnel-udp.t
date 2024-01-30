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
proxy.connect.emit-proxy-status: ON
access-log:
  path: /dev/stdout
  format: '\%h \%l \%u \%t \"\%r\" \%s \%b \%{upgrade}i'
EOT
    wait_port({port => $quic_port, proto => 'udp'});
    $tunnel_server->{quic_port} = $quic_port;
    $tunnel_server;
};

# setup H2O that acts as a reverse proxy to the UDP tunnel server
my $proxy_server = do {
    my $quic_port = empty_port({
        host  => "127.0.0.1",
        proto => "udp",
    });
    my $proxy_server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/h1/":
        proxy.reverse.url: http://127.0.0.1:@{[$tunnel_server->{port}]}
      "/h1s/":
        proxy.reverse.url: https://127.0.0.1:@{[$tunnel_server->{tls_port}]}
      "/h2/":
        proxy.reverse.url: https://127.0.0.1:@{[$tunnel_server->{tls_port}]}
        proxy.http2.ratio: 100
      "/h3/":
        proxy.reverse.url: https://127.0.0.1:@{[$tunnel_server->{quic_port}]}
        proxy.http3.ratio: 100
proxy.ssl.verify-peer: OFF
proxy.tunnel: ON
access-log: /dev/stdout
EOT
    wait_port({port => $quic_port, proto => 'udp'});
    $proxy_server->{quic_port} = $quic_port;
    $proxy_server;
};

# determine UDP port to be used by h2o-httpclient
my $tunnel_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

subtest "udp-draft03" => sub {
    for (
        ["h1", "-2 0 -x http://127.0.0.1:@{[$tunnel_server->{port}]}", 0],
        ["h1s", "-2 0 -x https://127.0.0.1:@{[$tunnel_server->{tls_port}]}", 0],
        ["h2", "-2 100 -x https://127.0.0.1:@{[$tunnel_server->{tls_port}]}", 0],
        ["h3", "-3 100 -x https://127.0.0.1:@{[$tunnel_server->{quic_port}]}", 0],
        ["h3+-X", "-3 100 -X $tunnel_port -x https://127.0.0.1:@{[$tunnel_server->{quic_port}]}", 1],
    ) {
        my ($name, $args) = @$_;
        my $cmd = "$client_prog -k -m CONNECT-UDP $args 127.0.0.1:@{[$udp_server->{port}]}";
        doit($name, $cmd, 200, sub {
            my $payload = shift;
            "\0". chr(length $payload) . $payload; # only supports payload up to 63 bytes
        });
    }
};

subtest "udp-rfc9298" => sub {
    my $doit = sub {
        my ($server, $path_prefix) = @_;
        for (
            ["h1", "-2 0 -m GET http://127.0.0.1:@{[$server->{port}]}$path_prefix", 101],
            ["h1s", "-2 0 -m GET https://127.0.0.1:@{[$server->{tls_port}]}$path_prefix", 101],
            ["h2", "-2 100 -m CONNECT https://127.0.0.1:@{[$server->{tls_port}]}$path_prefix", 200],
            ["h3", "-3 100 -m CONNECT https://127.0.0.1:@{[$server->{quic_port}]}$path_prefix", 200],
            ["h3+-X", "-3 100 -X $tunnel_port -m CONNECT https://127.0.0.1:@{[$server->{quic_port}]}$path_prefix", 200],
        ) {
            my ($name, $args_url_prefix, $status_expected) = @$_;
            plan skip_all => "proxy cannot forward connect-udp over H3"
                if $path_prefix ne '' && $args_url_prefix =~ /^-3 /;
            my $cmd = "$client_prog --upgrade connect-udp -k $args_url_prefix/rfc9298/127.0.0.1/@{[$udp_server->{port}]}/";
            doit($name, $cmd, $status_expected, sub {
                my $payload = shift;
                "\0" . chr(1 + length $payload) . "\0" . $payload; # only supports payload up to 63 bytes
            });
        }
    };
    subtest "direct" => sub {
        $doit->($tunnel_server, "");
    };
    subtest "via-proxy" => sub {
        for my $path_prefix (qw(/h1 /h1s /h2 /h3)) {
            subtest $path_prefix => sub {
                $doit->($proxy_server, $path_prefix);
            };
        }
    };
    subtest "h3-proxy-rejection" => sub {
        my $cmd = "$client_prog --upgrade connect-udp -k -3 100 -m CONNECT https://127.0.0.1:@{[$proxy_server->{quic_port}]}/h1/rfc9298/127.0.0.1/@{[$udp_server->{port}]}/";
        open my $fh, "|-", "$cmd > $tempdir/out 2>&1"
            or die "spawn error ($?) for command: $cmd";
        sleep 0.5;
        undef $fh;
        my $resp = do {
            open my $fh, "<", "$tempdir/out"
                or die "failed to open file:$tempdir/out:$!";
            local $/;
            <$fh>;
        };
        like $resp, qr{^HTTP/3 421}, "got 421";
    };
    subtest "broken-request" => sub {
        # just test h1 and call it a day
        plan skip_all => "nc not found"
            unless prog_exists("nc");
        my $resp = `echo "GET /rfc9298/host/invalid-port/ HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: connect-udp\r\n\r\n" | nc 127.0.0.1 $tunnel_server->{port} 2>&1`;
        like $resp, qr{HTTP/1\.1 400 .*\r\nproxy-status: h2o; error=http_request_error; details="invalid URI"}s;
    };
};

sub doit {
    my ($name, $cmd, $status_expected, $to_capsule) = @_;

    my $use_sock = !!($cmd =~ /(^| )-X /s);

    subtest $name => sub {
        open my $client, "|-", "$cmd > $tempdir/out 2>&1"
            or die "spawn error ($?) for command: $cmd";
        sleep 0.5;

        local $SIG{PIPE} = sub {}; # $client may exit early but we do not want to get killed by SIGPIPE when writing to it

        if ($use_sock) {
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
