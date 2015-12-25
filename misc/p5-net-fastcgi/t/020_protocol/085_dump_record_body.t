#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 64;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Constant', qw[:all]);
    use_ok('Net::FastCGI::Protocol', qw[:all]);
}

my @KNOWN_TYPES = (
    FCGI_BEGIN_REQUEST,
    FCGI_ABORT_REQUEST,
    FCGI_END_REQUEST,
    FCGI_PARAMS,
    FCGI_STDIN,
    FCGI_STDOUT,
    FCGI_STDERR,
    FCGI_DATA,
    FCGI_GET_VALUES,
    FCGI_GET_VALUES_RESULT,
    FCGI_UNKNOWN_TYPE,
);

foreach my $type (@KNOWN_TYPES) {
    like dump_record_body($type, 0), qr/\A\{ $FCGI_TYPE_NAME[$type]\, \s+ 0/x;
}

foreach my $type (FCGI_PARAMS, FCGI_GET_VALUES, FCGI_GET_VALUES_RESULT) {
    my $name = $FCGI_TYPE_NAME[$type];
    {
        my $dump = dump_record_body($type, 1, '');
        like $dump, qr/\A \{ $name\, \s+ 1\, \s ""/x;
    }
    {
        my $dump = dump_record_body($type, 1, build_params({ '' => '' }));
        like $dump, qr/\A \{ $name\, \s+ 1\, \s "\\000\\000"/x;
    }
    {
        my $dump = dump_record_body($type, 1, build_params({ 'Foo' => '' }));
        like $dump, qr/\A \{ $name\, \s+ 1\, \s "\\003\\000Foo"/x;
    }
    {
        my $dump = dump_record_body($type, 1, build_params({ "Foo\r\n" => "\x01\x02" }));
        like $dump, qr/\A \{ $name\, \s+ 1\, \s "\\005\\002Foo\\r\\n\\x01\\x02/x;
    }
    {
        my $dump = dump_record_body($type, 1, build_params({ 'x' => 'y' x 128 }));
        like $dump, qr/\A \{ $name\, \s+ 1\, \s "\\001\\200\\000\\000\\200 x y+/x;
    }
    {
        my $dump = dump_record_body($type, 1, "\001\001");
        like $dump, qr/\A \{ $name\, \s+ 1\, \s Malformed \s FCGI_NameValuePair/x;
    }
}

# Streams
{
    my @tests = (
        [ FCGI_STDIN, 1, "Foo\r\n\t",
          qr/\A \{ FCGI_STDIN\, \s+ 1\, \s \"Foo\\r\\n\\t/x ],
        [ FCGI_STDOUT, 1, "\x00\x01\x02\x03\x04\x05\x06\x07",
          qr/\A \{ FCGI_STDOUT\, \s+ 1\, \s \"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07/x ],
        [ FCGI_STDERR, 1, "Foo \x01\x02 Bar\n",
          qr/\A \{ FCGI_STDERR\, \s+ 1\, \s \"Foo\x20\\x01\\x02\x20Bar\\n/x ],
        [ FCGI_DATA, 1, 'x' x 80,
          qr/\A \{ FCGI_DATA\, \s+ 1\, \s \" x+ \s \.\.\./x ],
    );

    foreach my $test (@tests) {
        my ($type, $request_id, $content, $expected) = @$test;
        my $dump = dump_record_body($type, $request_id, $content);
        like $dump, $expected;
    }
}

# FCGI_BEGIN_REQUEST
{
    my @tests = (
        [ build_begin_request_body(FCGI_RESPONDER, FCGI_KEEP_CONN),
          qr/\A \{ FCGI_BEGIN_REQUEST\, \s+ 1\, \s \{ FCGI_RESPONDER\, \s+ FCGI_KEEP_CONN\}/x ],
        [ build_begin_request_body(FCGI_FILTER, FCGI_KEEP_CONN | 0x10),
          qr/\A \{ FCGI_BEGIN_REQUEST\, \s+ 1\, \s \{ FCGI_FILTER\, \s+ FCGI_KEEP_CONN|0x10\}/x ],
        [ build_begin_request_body(FCGI_AUTHORIZER, 0),
          qr/\A \{ FCGI_BEGIN_REQUEST\, \s+ 1\, \s \{ FCGI_AUTHORIZER\, \s+ 0\}/x ],
        [ build_begin_request_body(0, 0x80),
          qr/\A \{ FCGI_BEGIN_REQUEST\, \s+ 1\, \s \{ 0x0000\, \s+ 0x80\}/x ],
    map([ $_,
          qr/\A \{ FCGI_BEGIN_REQUEST\, \s+ 1\, \s \{ Malformed \s FCGI_BeginRequestBody/x ],
          ('', "\x00" x 10)),
    );

    foreach my $test (@tests) {
        my ($content, $expected) = @$test;
        my $dump = dump_record_body(FCGI_BEGIN_REQUEST, 1, $content);
        like $dump, $expected;
    }
}

# FCGI_END_REQUEST
{
    my @tests = (
        [ build_end_request_body(10, 0x80),
          qr/\A \{ FCGI_END_REQUEST\, \s+ 1\, \s \{ 10\, \s+ 0x80\}/x ],
    map([ $_,
          qr/\A \{ FCGI_END_REQUEST\, \s+ 1\, \s \{ Malformed \s FCGI_EndRequestBody/x ],
          ('', "\x00" x 10)),
    map([ build_end_request_body(0, $_),
          qr/\A \{ FCGI_END_REQUEST\, \s+ 1\, \s \{ 0\, \s+ $FCGI_PROTOCOL_STATUS_NAME[$_]\}/x ],
          (0..3)),
    );

    foreach my $test (@tests) {
        my ($content, $expected) = @$test;
        my $dump = dump_record_body(FCGI_END_REQUEST, 1, $content);
        like $dump, $expected;
    }
}

# FCGI_UNKNOWN_TYPE
{
    my @tests = (
        [ build_unknown_type_body(0),
          qr/\A \{ FCGI_UNKNOWN_TYPE\, \s+ 0\, \s \{ 0/x ],
    map([ build_unknown_type_body($_),
          qr/\A \{ FCGI_UNKNOWN_TYPE\, \s+ 0\, \s \{ $FCGI_TYPE_NAME[$_]/x ],
          @KNOWN_TYPES),
    map([ $_,
          qr/\A \{ FCGI_UNKNOWN_TYPE\, \s+ 0\, \s \{ Malformed \s FCGI_UnknownTypeBody/x ],
          ('', "\x00" x 10)),
    );

    foreach my $test (@tests) {
        my ($content, $expected) = @$test;
        my $dump = dump_record_body(FCGI_UNKNOWN_TYPE, 0, $content);
        like $dump, $expected;
    }
}


throws_ok { dump_record_body()               } qr/^Usage: /;
throws_ok { dump_record_body(0, 0, undef, 0) } qr/^Usage: /;

