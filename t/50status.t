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

subtest "json hander noreqs" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /s:
        status: ON
EOT

    my $resp = `curl --silent -o /dev/stderr 'http://127.0.0.1:$server->{port}/s/json?show=main|errors' 2>&1 > /dev/null`;
    my $jresp = decode_json("$resp");
    is $jresp->{'connections'}, 1, "One connection";
    is $jresp->{'requests'}, undef, "Zero request";
    is $jresp->{'http1-errors-404'}, 0, "Internal errors monitoring";
};


done_testing();
