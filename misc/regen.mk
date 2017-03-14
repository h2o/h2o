define FATPACK_SHEBANG
#! /bin/sh
exec $${H2O_PERL:-perl} -x $$0 "$$@"
#! perl
endef
export FATPACK_SHEBANG

all: tokens lib/handler/mruby/embedded.c.h lib/http2/hpack_huffman_table.h lib/handler/file/templates.c.h clang-format-all share/h2o/start_server share/h2o/fastcgi-cgi share/h2o/ca-bundle.crt

tokens:
	misc/tokens.pl

lib/handler/mruby/embedded.c.h: misc/embed_mruby_code.pl \
                                lib/handler/mruby/embedded/core.rb \
                                lib/handler/mruby/embedded/http_request.rb \
                                lib/handler/mruby/embedded/chunked.rb
	misc/embed_mruby_code.pl $^ > $@
	clang-format -i $@

lib/http2/hpack_huffman_table.h: misc/mkhufftbl.py
	python misc/mkhufftbl.py > $@

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

share/h2o/ca-bundle.crt: FORCE
	cd share/h2o; \
	../../misc/mk-ca-bundle.pl; \
	rm -f certdata.txt

FORCE:

.PHONY: tokens clang-format-all FORCE
