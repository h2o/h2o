use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'h2specd not found'
    unless prog_exists('h2specd');

my $client = bindir() . "/examples-httpclient";

plan skip_all => 'httpclient not found'
    unless -x $client;

my $output = `h2specd --tls --cert-file examples/h2o/server.crt --cert-key-file examples/h2o/server.key --exec '$client -t 1 -k -r 100'`;
unlike $output, qr/Failures:/;

done_testing();
