use strict;
use warnings;
use Cwd qw(abs_path);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

my $quic_port = $server->{quic_port};

local $ENV{H2O_ROOT} = abs_path(".");
my $resp = `$client_prog -3 100 https://127.0.0.1:$quic_port 2>&1`;

is $? >> 8, 1, "h2o-httpclient exits with certificate verification failure";
like $resp, qr{(?:^|/)h2o-httpclient: invalid certificate$}m, "reports certificate-specific error";

done_testing;
