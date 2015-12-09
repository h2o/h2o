package myconfig;

use strict;

BEGIN {
    $ENV{NET_FASTCGI_PP} = 0 + !(-e "XS.xs" || -e "../XS.xs");
}

1;
