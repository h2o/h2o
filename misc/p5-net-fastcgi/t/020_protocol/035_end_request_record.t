#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 4;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_end_request_record ]);
}

my @tests = (
    # octets                                                               request_id     app_status  protocol_status
    [ "\x01\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",           0,             0,               0 ],
    [ "\x01\x03\xFF\xFF\x00\x08\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\x00\x00",      0xFFFF,    0xFFFFFFFF,            0xFF ],
);

foreach my $test (@tests) {
    my $expected = $test->[0];
    my $got      = build_end_request_record(@$test[1..3]);
    is_hexstr($got, $expected, 'build_end_request_record()');
}

throws_ok { build_end_request_record() } qr/^Usage: /;

