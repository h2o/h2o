use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(sleep);
use Net::EmptyPort qw(check_port empty_port);
use Protocol::HTTP2::Client;
use File::Temp qw(tempfile);
use JSON;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;
my ($port, $tls_port) = empty_ports(2, { host => "127.0.0.1" });

my ($conffh, $conffn) = tempfile(UNLINK => 1);
print $conffh <<"EOT";
num-threads: 1
max-connections: 11
soft-connection-limit: 5
soft-connection-limit.min-age: 1

# Set timeouts high enough so they don't interfere with tests
http1-request-timeout: 60
http2-idle-timeout: 60
http3-idle-timeout: 60

listen:
  host: 127.0.0.1
  port: $port

listen: &ssl_listen
  host: 127.0.0.1
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt

listen:
 <<: *ssl_listen
 type: quic

hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

my ($guard, $pid) = spawn_server(
    argv     => [ bindir() . "/h2o", "-c", $conffn ],
    is_ready => sub {
        check_port($port);
    },
);

sub connections_count {
    my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$port/s/json 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    return $jresp->{'connections'}, $jresp->{'active-connections'}, $jresp->{'idle-connections'}
}

sub is_connections_count {
    my %args = @_;
    my $expected_total = $args{total};
    my $expected_active = $args{active};
    my $expected_idle = $args{idle};

    my ($total, $active, $idle) = connections_count();
    is $total, $expected_total, "assert total";
    is $active, $expected_active, "assert active";
    is $idle, $expected_idle, "assert idle";
}

subtest 'test connection stats' => sub {
    my @conns;

    for (1..3) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        push @conns, $conn;
    }

    sleep(2);

    is_connections_count(total => 4, active => 1, idle => 3);
};

subtest 'test http1 soft-connection-limit' => sub {
    my @conns;

    for (1..10) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        push @conns, $conn;
    }

    sleep(2);

    is_connections_count(total => 5, active => 1, idle => 4);
};

subtest 'test http2 soft-connection-limit' => sub {

    my @conns;
    for (1..10) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        my $client = Protocol::HTTP2::Client->new;

        $client->request(
            ':scheme'    => 'http',
            ':authority' => 'localhost:8000',
            ':path'      => '/',
            ':method'    => 'GET',
        );
        while ( my $frame = $client->next_frame ) {
            $conn->write($frame);
        }

        push @conns, $conn;
    }

    sleep(2);

    is_connections_count(total => 5, active => 1, idle => 4);
};

subtest 'test http3 soft-connection-limit' => sub {
    # Create connections up to soft-connection-limit
    for (1..10) {
        system("perl", "t/udp-generator.pl", "127.0.0.1", "$tls_port", "t/assets/quic-decryptable-initial.bin", "t/assets/quic-initial-w-corrupted-scid.bin") == 0 or die "Failed to launch udp-generator";
    }
    sleep(2);

    # Note: QUIC connections are not disposed of imediatly
    # send a request to trigger culling, then verify
    system("perl", "t/udp-generator.pl", "127.0.0.1", "$tls_port", "t/assets/quic-decryptable-initial.bin", "t/assets/quic-initial-w-corrupted-scid.bin") == 0 or die "Failed to launch udp-generator";
    sleep(2);

    is_connections_count(total => 6, active => 1, idle => 5);

    # Create one more connection
    system("perl", "t/udp-generator.pl", "127.0.0.1", "$tls_port", "t/assets/quic-decryptable-initial.bin", "t/assets/quic-initial-w-corrupted-scid.bin") == 0 or die "Failed to launch udp-generator";
    sleep(2);

    is_connections_count(total => 6, active => 1, idle => 5);
};

done_testing;
