define FATPACK_SHEBANG
#! /bin/sh
exec perl -x $$0 "$$@"
#! perl
endef
export FATPACK_SHEBANG

all: tokens lib/handler/file/templates.c.h clang-format-all share/h2o/start_server share/h2o/fastcgi-cgi

tokens:
	misc/tokens.pl

lib/handler/file/templates.c.h: misc/picotemplate-conf.pl lib/handler/file/_templates.c.h
	misc/picotemplate/picotemplate.pl --conf misc/picotemplate-conf.pl lib/handler/file/_templates.c.h || exit 1
	clang-format -i $@

clang-format-all:
	misc/clang-format-all.sh

share/h2o/start_server: FORCE
	cd misc/p5-Server-Starter; \
	fatpack-simple --shebang "$$FATPACK_SHEBANG" -o ../../$@ script/start_server

share/h2o/fastcgi-cgi: FORCE
	cd misc/p5-net-fastcgi; \
	fatpack-simple --shebang "$$FATPACK_SHEBANG" -o ../../$@ ../fastcgi-cgi.pl

FORCE:

.PHONY: tokens clang-format-all FORCE
