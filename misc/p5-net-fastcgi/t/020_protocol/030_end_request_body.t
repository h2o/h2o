#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 9;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_end_request_body
                                         parse_end_request_body ]);
}

my @tests = (
    # octets                                app_status  protocol_status
    [ "\x00\x00\x00\x00\x00\x00\x00\x00",            0,               0 ],
    [ "\xFF\xFF\xFF\xFF\xFF\x00\x00\x00",   0xFFFFFFFF,            0xFF ],
);

foreach my $test (@tests) {
    my $expected = $test->[0];
    my $got      = build_end_request_body(@$test[1..2]);
    is_hexstr($got, $expected, 'build_end_request_body()');
}

foreach my $test (@tests) {
    my @expected = @$test[1..2];
    my @got      = parse_end_request_body($test->[0]);
    is_deeply(\@got, \@expected, "parse_end_request_body()");
}


throws_ok { parse_end_request_body("")    } qr/^FastCGI: Insufficient .* FCGI_EndRequestBody/;
throws_ok { parse_end_request_body(undef) } qr/^FastCGI: Insufficient .* FCGI_EndRequestBody/;

throws_ok { build_end_request_body() } qr/^Usage: /;
throws_ok { parse_end_request_body() } qr/^Usage: /;

