#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 18;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Constant', qw[:all]);
    use_ok('Net::FastCGI::Protocol', qw[ build_header
                                         build_record
                                         get_record_length ]);
}


is get_record_length(undef), 0, 'get_record_length(undef)';

{
    for my $len (0..7) {
        is get_record_length("\x00" x $len), 0, qq<get_record_length("\\x00" x $len)>;
    }
}

{
    for my $len (8, 16, 32, 64) {
        my $record = build_record(0, 0, "\x00" x $len);
        is get_record_length($record), FCGI_HEADER_LEN + $len;
    }
}

{
    my $header = build_header(0, 0, 8192, 250);
    is get_record_length($header), FCGI_HEADER_LEN + 8192 + 250;
}

# get_record_length(octets)
for (0, 2) {
    throws_ok { get_record_length((1) x $_) } qr/^Usage: /;
}

