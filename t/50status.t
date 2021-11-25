use strict;
use warnings;
use Test::More;
use t::Util;
use JSON;
use File::Temp qw(tempdir);
use Net::EmptyPort qw/check_port/;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "default json handler" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT
    sleep 1; # wait for the spawn checker to disconnect
    my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/s/json 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    my @requests = @{$jresp->{'requests'}};
    is $jresp->{'connections'}, 1, "One connection";
    is scalar @requests, 1, "One request";
};

subtest "json hander without requests" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

    sleep 1; # wait for the spawn checker to disconnect
    my $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/s/json?show=main,events' 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    is $jresp->{'connections'}, 1, "One connection";
    is $jresp->{'requests'}, undef, "Requests not present";
    is $jresp->{'status-errors.404'}, 0, "Internal errors monitoring";
};

subtest "json hander check 404 error counter" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

    sleep 1; # wait for the spawn checker to disconnect
    my $resp;
    $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/beeb98fcf148317be5fe5d763c658bc9ea9c087a' 2>&1 > /dev/null`;
    $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/s/json?show=events' 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    is $jresp->{'connections'}, undef, "Connections not present";
    is $jresp->{'requests'}, undef, "Requests not present";
    is $jresp->{'status-errors.404'}, 1, "Found the 404 error";
};

subtest "duration stats" => sub {
    my $server = spawn_h2o(<< "EOT");
duration-stats: ON
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

    sleep 1; # wait for the spawn checker to disconnect
    my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/s/json?noreqs 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    my @nr_requests = @{ $jresp->{'requests'} };
    is $jresp->{'connections'}, 1, "One connection";
    is scalar @nr_requests, 1, "One request";
    is $jresp->{'status-errors.404'}, 0, "Additional errors";
    is $jresp->{'connect-time-0'}, 0, "Duration stats";
};

subtest "ssl stats" => sub {
    plan skip_all => "openssl too old"
        unless (() = `openssl s_client -help 2>&1` =~ /^ -(tls1_1|tls1_2|alpn)\s/mg) == 3;

    my $setup = sub {
        my ($port, $tls_port) = empty_ports(2, { host => "0.0.0.0" });
        my $server = spawn_h2o_raw(<< "EOT", [$port]); # omit tls_port check which causes a handshake
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
listen:
  host: 0.0.0.0
  port: $port
listen:
  host: 0.0.0.0
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    min-version: tlsv1.2
    max-version: tlsv1.2
EOT
        return ($server, $port, $tls_port);
    };

    subtest 'basic' => sub {
        my ($server, $port, $tls_port) = $setup->();

        my $build_req = sub {
            my ($tlsver, $alpn) = @_;
            "(echo GET / HTTP/1.0; echo) | openssl s_client -$tlsver -alpn $alpn -connect 127.0.0.1:$tls_port > /dev/null";
        };

        # error by TLS minimum version
        system $build_req->('tls1_1', 'http/1.1');
        # alpn
        system $build_req->('tls1_2', 'http/1.1');
        system $build_req->('tls1_2', 'h2');

        my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$port/s/json?show=events,ssl 2>&1 > /dev/null`;
        my $jresp = decode_json($resp);
        is $jresp->{'ssl.errors'}, 1, 'ssl.errors';
        is $jresp->{'ssl.alpn.h1'}, 1, 'ssl.alpn.h1';
        is $jresp->{'ssl.alpn.h2'}, 1, 'ssl.alpn.h2';
    };

    subtest 'handshake' => sub {
        plan skip_all => "could not find openssl"
            unless prog_exists("openssl");
        my $tempdir = tempdir(CLEANUP => 1);

        my ($server, $port, $tls_port) = $setup->();

        # full handshake
        `openssl s_client -no_ticket -sess_out $tempdir/session -connect 127.0.0.1:$tls_port < /dev/null`;
        # resume handshake
        `openssl s_client -no_ticket -sess_in $tempdir/session  -connect 127.0.0.1:$tls_port < /dev/null`;

        my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$port/s/json?show=ssl 2>&1 > /dev/null`;
        my $jresp = decode_json($resp);
        is $jresp->{'ssl.handshake.full'}, 1, 'ssl.handshake.full';
        is $jresp->{'ssl.handshake.resume'}, 1, 'ssl.handshake.resume';
        ok $jresp->{'ssl.handshake.accumulated-time.full'}, 'ssl.handshake.accumulated-time.full';
        ok $jresp->{'ssl.handshake.accumulated-time.resume'}, 'ssl.handshake.accumulated-time.resume';
    };
};


subtest "json internal request bug (duplication of durations and events)" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        << "EOT";
duration-stats: ON
hosts:
  default:
    paths:
      /server-status:
        status: ON
      /server-status2:
        status: ON
EOT
    });

    {
        my $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/server-status/json?show=durations,events,main' 2>&1 > /dev/null`;
        is scalar @{[ $resp =~ m!"status-errors.400":!g ]}, 1, "only once";
        is scalar @{[ $resp =~ m!"connect-time-0":!g ]}, 1, "only once";
    }

    {
        my $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/server-status2/json?show=durations,events,main' 2>&1 > /dev/null`;
        is scalar @{[ $resp =~ m!"status-errors.400":!g ]}, 1, "only once";
        is scalar @{[ $resp =~ m!"connect-time-0":!g ]}, 1, "only once";
    }
};


done_testing();
