use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port wait_port);
use Test::More;
use t::Util;
use Time::HiRes qw(sleep);

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;


sub create_tunnel {
    my ($proto, $origin_port, $proxy_port, $extra_args) = @_;

    my ($tunnel_port) = empty_ports(1, { host  => "127.0.0.1", proto => "udp"});
    my $tunnel = spawn_forked(sub {
        exec("$client_prog -k -$proto 100 $extra_args -X $tunnel_port -x https://127.0.0.1:$proxy_port 127.0.0.1:$origin_port") or die "Failed to exec";
    });

    return +{ tunnel => $tunnel, port => $tunnel_port,};
}

sub test_udp_exchange {
    my $tunnel_port = shift;
    my $resp = `$client_prog -o /dev/null -3 100 https://127.0.0.1:$tunnel_port/echo-query 2>&1`;
    like $resp, qr{^HTTP/3 200}s, "200 response";
}

sub setup_test {
    my $tempdir = tempdir(CLEANUP => 1);
    my $quic_port = empty_port({
            host  => "127.0.0.1",
            proto => "udp",
        });
    my $tls_port = empty_port();
    my $origin_quic_port = empty_port({
            host  => "127.0.0.1",
            proto => "udp",
        });
    my $sock_path = "$tempdir/prot.sock";


    my $upstream_port = empty_port();
    my $upstream = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($upstream_port);
        },
    );


    my $conf = << "EOT";
listen:
  type: quic
  port: $origin_quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
num-threads: 1
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
access-log: /dev/null # enable logging
EOT

    my $origin = spawn_h2o($conf);
    my $server = spawn_h2o_raw(<< "EOT");
num-threads: 2

listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
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


    my $ret; $ret = +{
        origin_quic_port => $origin_quic_port,
        origin_tls_port => $origin->{tls_port},
        proxy_tls_port => $tls_port,
        proxy_quic_port => $quic_port,
        tempdir => $tempdir,
        origin => $origin,
        server => $server,
        upstream => $upstream,
    };
    return $ret;
}

# Speed up h2o shutdown.
sub cleanup_test {
    my $test = shift;
    kill 'KILL', $test->{origin}->{pid};
    kill 'KILL', $test->{server}->{pid};
    $test->{origin} = undef;
    $test->{server} = undef;
}

subtest "udp-draft03" => sub {
    my $test = setup_test();

    wait_port({port => $test->{origin_quic_port}, proto => 'udp'});
    wait_port({port => $test->{proxy_quic_port}, proto => 'udp'});
    my $tunnel = create_tunnel("3", $test->{origin_quic_port}, $test->{proxy_quic_port}, "--connect-udp-draft03");
    foreach my $i (1..5) {
        test_udp_exchange($tunnel->{port});
    }
    cleanup_test($test);
};

subtest "udp-rfc9298" => sub {
    my $test = setup_test();

    wait_port({port => $test->{origin_quic_port}, proto => 'udp'});
    wait_port({port => $test->{proxy_quic_port}, proto => 'udp'});
    my $tunnel = create_tunnel("3", $test->{origin_quic_port}, $test->{proxy_quic_port}, "");
    foreach my $i (1..5) {
        test_udp_exchange($tunnel->{port});
    }
    cleanup_test($test);
};

# TODO cover proxying of CONNECT-UDP over HTTP2 (create_tunnel with HTTP2 as first argument)

done_testing;
