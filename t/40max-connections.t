use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $WAIT = 0.1;

subtest "single-connection" => sub {
    doit(1);
};

subtest "multiple-connections" => sub {
    doit(4);
};

done_testing;

sub doit {
    my $max_conn = shift;
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
max-connections: $max_conn
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    my $port = $server->{port};
    my $tls_port = $server->{tls_port};

    # establish connections to the maximum (and write partial requests so that the server would accept(2) the connections)
    my @conns;
    for (1..$max_conn) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        syswrite($conn, "GET / HTTP/1.0\r\n")
            or die "failed to write partial request:$!";
        push @conns, $conn;
    }

    sleep $WAIT;

    # create one more connection and send request
    my $blocked_conn = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$port",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    syswrite($blocked_conn, "GET / HTTP/1.0\r\n\r\n")
        or die "failed to write request:$!";

    sleep $WAIT;

    ok ! data_ready($blocked_conn), "succeeding conn is not handled";

    # close the preceeding connections
    while (@conns) {
        my $conn = shift @conns;
        syswrite($conn, "\r\n") or die "failed to complete partial request:$!";

        my $resp = do { local $/; <$conn> };
        like $resp, qr{^HTTP/1\.1 200 OK\r\n}s, "response is valid";
        close $conn;
    }

    sleep $WAIT;

    ok data_ready($blocked_conn), "succeeding conn should have been handled";

    my $resp = do { local $/; <$blocked_conn> };
    like $resp, qr{^HTTP/1\.1 200 OK\r\n}s, "response is valid";
}

sub data_ready {
    my $conn = shift;
    my $rfds = '';
    vec($rfds, fileno($conn), 1) = 1;
    my $nfound = select $rfds, undef, undef, 0;
    return $nfound != 0;
}
