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

sub run_client {
    my $args = shift;
    my $resp = `$client_prog -k -3 100 $args https://127.0.0.1:$quic_port/ 2>&1`;
    is $? >> 8, 0, "h2o-httpclient exits cleanly ($args)";
    like $resp, qr{^HTTP/3 200}m, "got 200 response ($args)";
}

subtest "default (qpack encoder dynamic table on)" => sub {
    run_client("");
};

subtest "qpack encoder dynamic table off" => sub {
    run_client("--http3-qpack-encoder-table-capacity 0");
};

done_testing;
