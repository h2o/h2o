#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 54;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Constant', qw[:all]);
    use_ok('Net::FastCGI::Protocol', qw[ build_header
                                         build_record
                                         build_stream
                                         parse_record ]);
}

my @records_ok = (
    [
      "\x01\x01\x00\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
      "\x00\x01\x00\x00\x00\x00\x00\x00",
      { type       => FCGI_BEGIN_REQUEST,
        request_id => 1,
        role       => FCGI_RESPONDER,
        flags      => 0 }
    ],
    [
      "\x01\x02\x00\x01\x00\x00\x00\x00",
      "",
      { type       => FCGI_ABORT_REQUEST,
        request_id => 1 }
    ],
    [
      "\x01\x03\x00\x01\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      { type            => FCGI_END_REQUEST,
        request_id      => 1,
        protocol_status => 0,
        app_status      => 0 }
    ],
    [
      "\x01\x04\x00d\x00\x0B\x05\x00FCGI_PARAMS\x00\x00\x00\x00\x00",
      "FCGI_PARAMS",
      { type       => FCGI_PARAMS,
        request_id => 100,
        content    => 'FCGI_PARAMS' }
    ],
    [
      "\x01\x05\x00\xC8\x00\x0A\x06\x00FCGI_STDIN\x00\x00\x00\x00\x00\x00",
      "FCGI_STDIN",
      { type       => FCGI_STDIN,
        request_id => 200,
        content    => 'FCGI_STDIN' }
    ],
    [
      "\x01\x06\x01\x2C\x00\x0B\x05\x00FCGI_STDOUT\x00\x00\x00\x00\x00",
      "FCGI_STDOUT",
      { type       => FCGI_STDOUT,
        request_id => 300,
        content    => 'FCGI_STDOUT' }
    ],
    [
      "\x01\x07\x01\x90\x00\x0B\x05\x00FCGI_STDERR\x00\x00\x00\x00\x00",
      "FCGI_STDERR",
      { type       => FCGI_STDERR,
        request_id => 400,
        content    => 'FCGI_STDERR' }
    ],
    [
      "\x01\x08\x01\xF4\x00\x09\x07\x00FCGI_DATA\x00\x00\x00\x00\x00\x00\x00",
      "FCGI_DATA",
      { type       => FCGI_DATA,
        request_id => 500,
        content    => 'FCGI_DATA' }
    ],
    [
      "\x01\x09\x00\x00\x00\x0D\x03\x00\x03\x03BarBaZ\x03\x00FOO\x00\x00\x00",
      "\x03\x03BarBaZ\x03\x00FOO",
      { type       => FCGI_GET_VALUES,
        request_id => FCGI_NULL_REQUEST_ID,
        values     => { FOO => '', Bar => 'BaZ' }
      }
    ],
    [
      "\x01\x0A\x00\x00\x00\x17\x01\x00\x04\x01BETA2\x05\x01ALPHA1\x05\x01GAMMA3\x00",
      "\x04\x01BETA2\x05\x01ALPHA1\x05\x01GAMMA3",
      { type       => FCGI_GET_VALUES_RESULT,
        request_id => FCGI_NULL_REQUEST_ID,
        values     => { ALPHA => 1, BETA => 2, GAMMA => 3 }
      }
    ],
    [
      "\x01\x0B\x00\x00\x00\x08\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00",
      "\x64\x00\x00\x00\x00\x00\x00\x00",
      { type         => FCGI_UNKNOWN_TYPE,
        request_id   => FCGI_NULL_REQUEST_ID,
        unknown_type => 100 }
    ],
    [
      "\x01\x6F\x00\xDE\x00\x04\x04\x00oops\x00\x00\x00\x00",
      "oops",
      { type       => 111,
        request_id => 222,
        content    => 'oops' }
    ],
    [
      "\x01\xFF\xFF\xFF\x00\x00\x00\x00",
      "",
      { type       => 0xFF,
        request_id => 0xFFFF }
    ],
);

foreach my $test (@records_ok) {
    my $expected = $test->[2];
    my $got      = parse_record($test->[0]);
    is_deeply($got, $expected, "parse_record() in scalar context");
}

foreach my $test (@records_ok) {
    my @expected = ($test->[2]->{type}, $test->[2]->{request_id}, $test->[1]);
    my @got      = parse_record($test->[0]);
    is_deeply(\@got, \@expected, "parse_record() in list context");
}

my @headers_malformed = (
    # type, request_id, content_length, padding_length
    [ FCGI_BEGIN_REQUEST,     0, 0, 0 ],
    [ FCGI_BEGIN_REQUEST,     1, 0, 0 ],
    [ FCGI_ABORT_REQUEST,     0, 0, 0 ],
    [ FCGI_END_REQUEST,       0, 0, 0 ],
    [ FCGI_END_REQUEST,       1, 0, 0 ],
    [ FCGI_PARAMS,            0, 0, 0 ],
    [ FCGI_STDIN,             0, 0, 0 ],
    [ FCGI_STDOUT,            0, 0, 0 ],
    [ FCGI_STDERR,            0, 0, 0 ],
    [ FCGI_DATA,              0, 0, 0 ],
    [ FCGI_GET_VALUES,        1, 0, 0 ],
    [ FCGI_GET_VALUES_RESULT, 1, 0, 0 ],
    [ FCGI_UNKNOWN_TYPE,      0, 0, 0 ],
    [ FCGI_UNKNOWN_TYPE,      1, 0, 0 ]
);

foreach my $test (@headers_malformed) {
    my $octets = build_header(@$test);
    throws_ok { parse_record($octets) } qr/^FastCGI: Malformed/;
}

{
    my $octets = build_header(FCGI_ABORT_REQUEST, 1, 8, 0) . "\x00" x 8;
    throws_ok { parse_record($octets) } qr/^FastCGI: Malformed/;
}

my @stream_types = (
    FCGI_PARAMS,
    FCGI_STDIN,
    FCGI_STDOUT,
    FCGI_STDERR,
    FCGI_DATA
);

foreach my $type (@stream_types) {
    my $expected = { type => $type, request_id => 1, content => '' };
    my $octets   = build_record($type, 1, '');
    my $got      = parse_record($octets);
    is_deeply($got, $expected, "parse_record(stream record) in scalar context");
}

foreach my $type (@stream_types) {
    my @expected = ($type, 1, '');
    my $octets   = build_record($type, 1, '');
    my @got      = parse_record($octets);
    is_deeply(\@got, \@expected, "parse_record(stream record) in list context");
}

throws_ok { parse_record() } qr/^Usage: /;

