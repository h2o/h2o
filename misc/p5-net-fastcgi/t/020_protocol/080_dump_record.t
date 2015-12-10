#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 9;
use Test::Exception;

BEGIN {
    use_ok('Net::FastCGI::Protocol', qw[build_record dump_record]);
}

{
    my $record = build_record(0, 0, "\x00\x01\x02\x03\x04\x05\x06\x07");
    my $dump   = dump_record($record);
    like $dump, qr/\A \{0x00, \s 0, \s "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"\}/x;
}

{
    my $record = build_record(0, 0, "\x00\x01\x02\x03\x04\x05\x06\x07");

    for my $len (0, 8) {
        my $dump = dump_record(substr($record, 0, $len));
        like $dump, qr/\A \{ Malformed \s FCGI_Record }/x, "Insufficient octets";
    }
}

{
    for my $header ("\x00\x00\x00\x00\x00\x00\x00\x00", 
                    "\xFF\x00\x00\x00\x00\x00\x00\x00") {
        my $dump = dump_record($header);
        like $dump, qr/\A \{ Malformed \s FCGI_Record }/x, "Protocol version mismatch";
    }
}

# dump_record(type, request_id [, content]) deprecated
{
    my $dump   = dump_record(0, 0);
    like $dump, qr/\A \{0x00, \s 0, \s ""\}/x;
}
{
    my $dump   = dump_record(0, 0, "\x00\x01\x02\x03\x04\x05\x06\x07");
    like $dump, qr/\A \{0x00, \s 0, \s "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"\}/x;
}

# dump_record(octets)
throws_ok { dump_record() } qr/^Usage: /;

