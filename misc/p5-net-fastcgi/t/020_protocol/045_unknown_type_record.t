#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 4;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_unknown_type_record ]);
}

my @tests = (
    # octets                                                               type
    [ "\x01\x0B\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",     0 ],
    [ "\x01\x0B\x00\x00\x00\x08\x00\x00\xFF\x00\x00\x00\x00\x00\x00\x00",  0xFF ],
);

foreach my $test (@tests) {
    my $expected = $test->[0];
    my $got      = build_unknown_type_record($test->[1]);
    is_hexstr($got, $expected, 'build_unknown_type_record()');
}

throws_ok { build_unknown_type_record() } qr/^Usage: /;

