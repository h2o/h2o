#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 33;
use Test::HexString;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Constant', qw[:all]);
    use_ok('Net::FastCGI::Protocol', qw[ build_header
                                         build_record
                                         build_stream
                                         parse_record_body ]);
}

my @ok = (
    [
        "\x00\x01\x01\x00\x00\x00\x00\x00",
        { type       => FCGI_BEGIN_REQUEST,
          request_id => 1,
          role       => 1,
          flags      => 1 }
    ],
    [
        "\x00\x00\x00\x01\x01\x00\x00\x00",
        { type            => FCGI_END_REQUEST,
          request_id      => 1,
          app_status      => 1,
          protocol_status => 1 }
    ],
    [
        undef,
        { type            => FCGI_STDIN,
          request_id      => 1,
          content         => '' }
    ],
    [
        "",
        { type            => FCGI_PARAMS,
          request_id      => 1,
          content         => '' }
    ],
    [
        "\x01\x01A1\x01\x01B2",
        { type          => FCGI_GET_VALUES,
          request_id    => FCGI_NULL_REQUEST_ID,
          values        => { A => 1, B => 2 } }
    ],
    [
        undef,
        { type          => FCGI_GET_VALUES_RESULT,
          request_id    => FCGI_NULL_REQUEST_ID,
          values        => {} }
    ]
);

foreach my $test (@ok) {
    my $exp = $test->[1];
    my $got = parse_record_body($exp->{type}, $exp->{request_id}, $test->[0]);
    is_deeply($got, $exp, "parse_record_body()");
}

my @malformed = (
    # type, request_id
    [ FCGI_BEGIN_REQUEST,     0 ],
    [ FCGI_END_REQUEST,       0 ],
    [ FCGI_PARAMS,            0 ],
    [ FCGI_STDIN,             0 ],
    [ FCGI_STDOUT,            0 ],
    [ FCGI_STDERR,            0 ],
    [ FCGI_DATA,              0 ],
    [ FCGI_GET_VALUES,        1 ],
    [ FCGI_GET_VALUES_RESULT, 1 ],
    [ FCGI_UNKNOWN_TYPE,      1 ]
);

foreach my $test (@malformed) {
    my ($type, $request_id) = @$test;
    throws_ok { parse_record_body($type, $request_id, '') } qr/^FastCGI: Malformed/;
}

{
    my $content = "\x00" x (FCGI_MAX_CONTENT_LEN + 1);
    foreach my $type (0..12) {
        throws_ok { parse_record_body($type, 0, $content) } qr/^Invalid Argument: 'content' cannot exceed/;
    }
}

# parse_record_body(type, request_id, content)
for (0, 4) {
    throws_ok { parse_record_body((1) x $_) } qr/^Usage: /;
}

