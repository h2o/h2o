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

my $resp = `nghttp -v http://127.0.0.1:$server->{'port'}/ -H 'h\rost: host.example.com' 2>&1`;
like $resp, qr{.*error_code=NO_ERROR.*}, "No protocol error for a bogus header name";
like $resp, qr{.*:status: 400}, "400 bad headers sent";
like $resp, qr{found an invalid character in header name}, "Found expected error message";

$resp = `nghttp -v http://127.0.0.1:$server->{'port'}/ -H 'host: host.\rexample.com' 2>&1`;
like $resp, qr{.*error_code=NO_ERROR.*}, "No protocol error for a bogus header value";
like $resp, qr{.*:status: 400}, "400 bad headers sent";
like $resp, qr{found an invalid character in header value}, "Found expected error message";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/test/ -H 'host: host.example.com' -H'blah:1' -H'blah:2' -H'blah:3' 2>&1`;
like $resp, qr{.*error_code=NO_ERROR.*}, "No error for no bogus error value";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/test/ -H 'host: host.example.com' -H'bl\ah:1' -H'bl\ah:2' -H'bl\ah:3' 2>&1`;
like $resp, qr{.*error_code=NO_ERROR.*}, "No protocol error for repeated bogus headers";
like $resp, qr{.*:status: 400}, "400 bad headers sent";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/ -H ':bad: 1234' -H'x-reproxy-url: http://www.example.com' 2>&1`;
like $resp, qr{.*error_code=PROTOCOL_ERROR.*}, "Error for an invalid pseudo-header";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/test/ -H 'host: host.example.com' -H'bl\ah:1' -H':badpseudo:2' 2>&1`;
like $resp, qr{.*error_code=PROTOCOL_ERROR.*}, "Protocol error for an invalid pseudo-header, even when a bad header was present";

$resp = `nghttp -nv http://127.0.0.1:$server->{'port'}/test/ -H 'host: host.उदाहरण.com' 2>&1`;
like $resp, qr{.*error_code=NO_ERROR.*}, "No error for utf-8 in value";

done_testing();
