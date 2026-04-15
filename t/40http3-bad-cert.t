use strict;
use warnings;
use Cwd qw(abs_path);
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

wait_port({port => $quic_port, proto => 'udp'});

local $ENV{H2O_ROOT} = abs_path(".");
my $resp = `$client_prog -3 100 https://127.0.0.1:$quic_port 2>&1`;

is $? >> 8, 1, "h2o-httpclient exits with certificate verification failure";
like $resp, qr{(?:^|/)h2o-httpclient: invalid certificate$}m, "reports certificate-specific error";

done_testing;
