#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 9;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_unknown_type_body
                                         parse_unknown_type_body ]);
}

my @tests = (
    # octets                               type
    [ "\x00\x00\x00\x00\x00\x00\x00\x00",     0 ],
    [ "\xFF\x00\x00\x00\x00\x00\x00\x00",  0xFF ],
);

foreach my $test (@tests) {
    my $expected = $test->[0];
    my $got      = build_unknown_type_body($test->[1]);
    is_hexstr($got, $expected, 'build_unknown_type_body()');
}

foreach my $test (@tests) {
    my @expected = $test->[1];
    my @got      = parse_unknown_type_body($test->[0]);
    is_deeply(\@got, \@expected, "parse_unknown_type_body()");
}


throws_ok { parse_unknown_type_body("")    } qr/^^FastCGI: Insufficient .* FCGI_UnknownTypeBody/;
throws_ok { parse_unknown_type_body(undef) } qr/^^FastCGI: Insufficient .* FCGI_UnknownTypeBody/;

throws_ok { build_unknown_type_body() } qr/^Usage: /;
throws_ok { parse_unknown_type_body() } qr/^Usage: /;

