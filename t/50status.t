use strict;
use warnings;
use Test::More;
use t::Util;
use JSON;

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

    my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/s/json?noreqs 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    my @nr_requests = @{ $jresp->{'requests'} };
    is $jresp->{'connections'}, 1, "One connection";
    is scalar @nr_requests, 1, "One request";
    is $jresp->{'status-errors.404'}, 0, "Additional errors";
    is $jresp->{'connect-time-0'}, 0, "Duration stats";
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
