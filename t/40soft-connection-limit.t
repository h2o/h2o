use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(sleep);
use Net::EmptyPort qw(check_port);
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
    return $jresp->{'connections'}, $jresp->{'connections.active'}, $jresp->{'connections.idle'}, $jresp->{'connections.shutdown'}, $jresp->{'connections.idle-closed'}
}

sub is_connections_count {
    my %args = @_;
    my $expected_total = $args{total};
    my $expected_active = $args{active};
    my $expected_idle = $args{idle};
    my $expected_shutdown = $args{shutdown};
    my $expected_idle_closed = $args{idle_closed} || 0;

    my ($total, $active, $idle, $shutdown, $idle_closed) = connections_count();
    is $total, $expected_total, "assert total";
    is $active, $expected_active, "assert active";
    is $idle, $expected_idle, "assert idle";
    is $shutdown, $expected_shutdown, "assert shutdown";
    is $idle_closed, $expected_idle_closed, "assert idle closed";
}

subtest "http1" => sub {

    subtest 'stats-initial' => sub {
        my @conns;

        for (1..3) {
            my $conn = IO::Socket::INET->new(
                PeerAddr => "127.0.0.1:$port",
                Proto    => "tcp",
            ) or die "connection failed:$!";
            push @conns, $conn;
        }

        sleep(2);

        is_connections_count(total => 4, active => 4, idle => 0, shutdown => 0);

        # make sure that h2o sees the @conns being actively closed by the client (rather than evicting them as idle)
        undef @conns;
        sleep 1;
    };

    subtest 'stats-after-first-req' => sub {
        my @conns;

        for (1..3) {
            my $conn = IO::Socket::INET->new(
                PeerAddr => "127.0.0.1:$port",
                Proto    => "tcp",
            ) or die "connection failed:$!";
            $conn->syswrite("GET / HTTP/1.1\r\n\r\n");
            push @conns, $conn;
        }

        sleep(2);

        is_connections_count(total => 4, active => 1, idle => 3, shutdown => 0);

        # make sure that h2o sees the @conns being actively closed by the client (rather than evicting them as idle)
        undef @conns;
        sleep 1;
    };

    subtest 'soft-connection-limit' => sub {
        my @conns;

        for (1..10) {
            my $conn = IO::Socket::INET->new(
                PeerAddr => "127.0.0.1:$port",
                Proto    => "tcp",
            ) or die "connection failed:$!";
            $conn->syswrite("GET / HTTP/1.1\r\n\r\n");
            push @conns, $conn;
        }

        sleep(4);

        is_connections_count(total => 5, active => 1, idle => 4, shutdown => 0, idle_closed => 6);
    };

};

sleep(2); # add wait so that h2o will recognize the clos eof idle connections created above

subtest 'http2 soft-connection-limit' => sub {
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

    sleep(4);

    is_connections_count(total => 11, active => 1, idle => 4, shutdown => 6, idle_closed => 12);
};

sleep(2); # add wait so that h2o will recognize the clos eof idle connections created above

subtest 'http3 soft-connection-limit' => sub {
    my @conns;
    for (1..10) {
        # launch h2o-httpclient that immediately issues a request and then idles for 10 seconds before sending the next request
        open my $fh, "-|", "@{[bindir()]}/h2o-httpclient -3 100 -t 2 -d 10000 https://127.0.0.1:$tls_port/ 2> /dev/null"
            or die "failed to launch h2o-httpclient:$!";
        push @conns, $fh;
    }

    sleep(4);

    is_connections_count(total => 11, active => 1, idle => 4, shutdown => 6, idle_closed => 18);
};

done_testing;
