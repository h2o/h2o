#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 11;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_record ]);
}

my @tests = (
    # octets                                                               type  request_id                              content
    [ "\x01\x00\x00\x00\x00\x00\x00\x00",                                     0,          0,                               undef ],
    [ "\x01\xFF\xFF\xFF\x00\x00\x00\x00",                                  0xFF,     0xFFFF,                               undef ],
    [ "\x01\x01\x00\x01\x00\x01\x07\x00\x01\x00\x00\x00\x00\x00\x00\x00",     1,          1,                              "\x01" ],
    [ "\x01\x01\x00\x01\x00\x05\x03\x00\x01\x01\x01\x01\x01\x00\x00\x00",     1,          1,              "\x01\x01\x01\x01\x01" ],
    [ "\x01\x01\x00\x01\x00\x08\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01",     1,          1,  "\x01\x01\x01\x01\x01\x01\x01\x01" ],
);

foreach my $test (@tests) {
    my $expected = $test->[0];
    my $got      = build_record(@$test[1..3]);
    is_hexstr($got, $expected, 'build_record()');
}

{
    my $exp = "\x01\x01\x00\x02\x00\x00\x00\x00";
    my $got = build_record(1, 2);
    is_hexstr($got, $exp, 'build_record(1, 2)');
}

throws_ok { build_record( 0, 0, "\x00" x (0xFFFF + 1) ) } qr/^Invalid Argument: 'content' cannot exceed/;

# build_record(type, request_id [, content])
for (0..1, 4) {
    throws_ok { build_record((1) x $_) } qr/^Usage: /;
}

