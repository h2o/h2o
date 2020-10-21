use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(sleep);
use JSON;
use t::Util;

my $server = spawn_h2o(<< "EOT");
num-threads: 1
max-connections: 11
soft-connection-limit: 5
soft-connection-limit.min-age: 1
http1-request-timeout: 60
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

    my $port = $server->{port};

    # establish connections to the maximum (and write partial requests so that the server would accept(2) the connections)
    my @conns;
    for (1..10) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        push @conns, $conn;
    }

    sleep(2);

    my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/s/json 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    is $jresp->{'connections'}, 5, "Five connections";

    for (1..10) {
        my $conn = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port",
            Proto    => "tcp",
        ) or die "connection failed:$!";
        push @conns, $conn;
    }

    sleep(2);

    $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/s/json 2>&1 > /dev/null`;
    $jresp = decode_json("$resp");
    is $jresp->{'connections'}, 5, "Five connections";


    while (@conns) {
        close shift @conns;
    }
    done_testing;