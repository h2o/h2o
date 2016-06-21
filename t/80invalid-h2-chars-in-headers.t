use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

my $resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/ -H 'h\rost: host.example.com' 2>&1`;
like $resp, qr{.*error_code=PROTOCOL_ERROR.*}, "Got a protocol error for a bogus header name";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/ -H 'host: host.\rexample.com' 2>&1`;
like $resp, qr{.*error_code=PROTOCOL_ERROR.*}, "Got a protocol error for a bogus header value";

done_testing();
