#! /bin/sh

misc/tokens.pl || exit 1
misc/picotemplate/picotemplate.pl --conf misc/picotemplate-conf.pl lib/handler/file/_templates.c.h || exit 1
