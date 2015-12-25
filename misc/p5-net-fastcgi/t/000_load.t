#!perl

use strict;
use warnings;

use lib 't/lib', 'lib';
use myconfig;

use Test::More tests => 5;

BEGIN {
    use_ok('Net::FastCGI');
    use_ok('Net::FastCGI::Constant');
    use_ok('Net::FastCGI::IO');
    use_ok('Net::FastCGI::Protocol');

    if ( $ENV{NET_FASTCGI_PP} ) {
        use_ok('Net::FastCGI::Protocol::PP');
    }
    else {
        use_ok('Net::FastCGI::Protocol::XS');
    }
}

diag("Net::FastCGI $Net::FastCGI::VERSION, Perl $], $^X");
diag("NET_FASTCGI_PP=$ENV{NET_FASTCGI_PP}");



