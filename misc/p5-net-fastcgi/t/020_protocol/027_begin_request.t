#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 15;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_begin_request ]);
    use_ok('Net::FastCGI::Constant', qw[ :type :role ]);
}

{
    my $begin = "\x01\x01\x00\x01\x00\x08\x00\x00"  # FCGI_Header id=1
              . "\x00\x01\x00\x00\x00\x00\x00\x00"; # FCGI_BeginRequestBody role=FCGI_RESPONDER

    my $params = "\x01\x04\x00\x01\x00\x00\x00\x00"; # FCGI_Header type=FCGI_PARAMS

    {
        my $exp = $begin . $params;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, {});
        is_hexstr($got, $exp, q<build_begin_request(1, FCGI_RESPONDER, 0, {})>);
    }

    my $stdin = "\x01\x05\x00\x01\x00\x00\x00\x00"; # FCGI_Header type=FCGI_STDIN

    {
        my $exp = $begin . $params . $stdin;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, {}, '');
        is_hexstr($got, $exp, q<build_begin_request(1, FCGI_RESPONDER, 0, {}, '')>);
    }

    {
        my $exp = $begin . $params . $stdin;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, {}, undef);
        is_hexstr($got, $exp, q<build_begin_request(1, FCGI_RESPONDER, 0, {}, undef)>);
    }

    my $data = "\x01\x08\x00\x01\x00\x00\x00\x00"; # FCGI_Header type=FCGI_DATA

    {
        my $exp = $begin . $params . $stdin . $data;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, {}, '', undef);
        is_hexstr($got, $exp, q<build_begin_request(1, FCGI_RESPONDER, 0, {}, '', undef)>);
    }

    {
        my $exp = $begin . $params . $stdin . $data;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, {}, undef, '');
        is_hexstr($got, $exp, q<build_begin_request(1, FCGI_RESPONDER, 0, {}, undef, '')>);
    }
}

{
    my $begin = "\x01\x01\x00\x01\x00\x08\x00\x00"  # FCGI_Header id=1
              . "\x00\x01\x00\x00\x00\x00\x00\x00"; # FCGI_BeginRequestBody role=FCGI_RESPONDER

    my $params = "\x01\x04\x00\x01\x00\x08\x00\x00" # FCGI_Header type=FCGI_PARAMS
               . "\x03\x03FooBar"
               . "\x01\x04\x00\x01\x00\x00\x00\x00";

    {
        my $exp = $begin . $params;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' });
        is_hexstr($got, $exp, q!build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' })!);
    }

    my $stdin = "\x01\x05\x00\x01\x03\xFC\x04\x00" # FCGI_Header type=FCGI_STDIN
              . "x" x 1020 . "\0" x 4
              . "\x01\x05\x00\x01\x00\x00\x00\x00";
    {
        my $exp = $begin . $params . $stdin;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' }, 'x' x 1020);
        is_hexstr($got, $exp, q!build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' }, 'x' x 1020)!);
    }

    my $data = "\x01\x08\x00\x01\x04\x00\x00\x00" # FCGI_Header type=FCGI_DATA
             . "y" x 1024
             . "\x01\x08\x00\x01\x00\x00\x00\x00"; 

    {
        my $exp = $begin . $params . $stdin . $data;
        my $got = build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' }, 'x' x 1020, 'y' x 1024);
        is_hexstr($got, $exp, q!build_begin_request(1, FCGI_RESPONDER, 0, { Foo => 'Bar' }, 'x' x 1020, 'y' x 1024)!);
    }
}

# build_begin_request(request_id, role, flags, params [, stdin [, data]])
for (0..3, 7) {
    throws_ok { build_begin_request((1) x $_) } qr/^Usage: /;
}

