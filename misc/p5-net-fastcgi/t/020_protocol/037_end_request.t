#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 13;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[ build_end_request ]);
    use_ok('Net::FastCGI::Constant', qw[ :type :protocol_status ]);
}

{
    my $end = "\x01\x03\x00\x01\x00\x08\x00\x00" # FCGI_Header id=1
            . "\x00\x00\x00\x00\x00\x00\x00\x00" # FCGI_EndRequestBody
            ;

    {
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE);
        is_hexstr($got, $end, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE)>);
    }

    my $stdout = "\x01\x06\x00\x01\x00\x00\x00\x00"; # FCGI_Header type=FCGI_STDOUT

    {
        my $exp = $stdout . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, '');
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, '')>);
    }

    {
        my $exp = $stdout . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, undef);
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, undef)>);
    }

    my $stderr = "\x01\x07\x00\x01\x00\x00\x00\x00"; # FCGI_Header type=FCGI_STDERR

    {
        my $exp = $stdout . $stderr . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, '', undef);
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, '', undef)>);
    }

    {
        my $exp = $stdout . $stderr . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, undef, '');
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, undef, '')>);
    }
}

{
    my $end = "\x01\x03\x00\x01\x00\x08\x00\x00" # FCGI_Header id=1
            . "\x00\x00\x00\x00\x00\x00\x00\x00" # FCGI_EndRequestBody
            ;

    my $stdout = "\x01\x06\x00\x01\x03\xFC\x04\x00" # FCGI_Header type=FCGI_STDOUT
               . "x" x 1020 . "\0" x 4
               . "\x01\x06\x00\x01\x00\x00\x00\x00";

    {
        my $exp = $stdout . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, 'x' x 1020);
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, 'x' x 1020)>);
    }

    my $stderr = "\x01\x07\x00\x01\x04\x00\x00\x00" # FCGI_Header type=FCGI_STDERR
               . "y" x 1024
               . "\x01\x07\x00\x01\x00\x00\x00\x00";

    {
        my $exp = $stdout . $stderr . $end;
        my $got = build_end_request(1, 0, FCGI_REQUEST_COMPLETE, 'x' x 1020, 'y' x 1024);
        is_hexstr($got, $exp, q<build_end_request(1, 0, FCGI_REQUEST_COMPLETE, 'x' x 1020, 'y' x 1024)>);
    }
}

# build_end_request(request_id, app_status, protocol_status [, stdout [, stderr]])
for (0..2, 6) {
    throws_ok { build_end_request((1) x $_) } qr/^Usage: /;
}

