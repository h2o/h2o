#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 38;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_params
                                         check_params
                                         parse_params ]);
}

sub TRUE  () { !!1 }
sub FALSE () { !!0 }

my @tests = (
    # octets                                               params
    [ "",                                                  { }                               ],
    [ "\x00\x00",                                          { '' => '' },                     ],
    [ "\x01\x01\x31\x31",                                  {  1 =>  1 },                     ],
    [ "\x01\x01\x41\x42\x01\x01\x43\x44\x01\x01\x45\x46",  {  A => 'B', C => 'D', E => 'F' } ],
);

foreach my $test (@tests) {
    my ($expected, $params) = @$test;
    my $got = join '', map {
        build_params({ $_ => $params->{$_} })
    } sort keys %$params;
    is_hexstr($got, $expected, 'build_params()');
}

is_hexstr("\x03\x00foo", build_params({foo => undef}), 'build_params({foo => undef})');
is_hexstr("\x7F\x00" . "x" x 127, build_params({ "x" x 127 => '' }));
is_hexstr("\x00\x7F" . "x" x 127, build_params({ '' => "x" x 127 }));
is_hexstr("\x80\x00\x00\x80\x00" . "x" x 128, build_params({ "x" x 128 => '' }));
is_hexstr("\x00\x80\x00\x00\x80" . "x" x 128, build_params({ '' => "x" x 128 }));

foreach my $test (@tests) {
    my $expected = $test->[1];
    my $got      = parse_params($test->[0]);
    is_deeply($got, $expected, 'parse_params()');
}

foreach my $test (@tests) {
    my $octets = $test->[0];
    is(check_params($octets), TRUE, 'check_params(octets) eq TRUE');
}

my @insufficient = (
    "\x00",
    "\x01",
    "\x00\x01",
    "\x01\x00",
    "\x00\xFF",
    "\x01\xFF\x00",
    "\x00\x80\x00\x00\x80",
    "\x80\x00\x00\x80\x00",
);

foreach my $test (@insufficient) {
    throws_ok { parse_params($test) } qr/^FastCGI: Insufficient .* FCGI_NameValuePair/;
}

foreach my $test (@insufficient) {
    is(check_params($test), FALSE, 'check_params(octets) eq FALSE');
}

is(check_params(undef), FALSE, 'check_params(undef) eq FALSE');

throws_ok { check_params() } qr/^Usage: /;
throws_ok { build_params() } qr/^Usage: /;
throws_ok { parse_params() } qr/^Usage: /;

