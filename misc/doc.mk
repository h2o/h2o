BINARY_DIR=..
VPATH=../srcdoc
OUTPUT=\
    index.html \
    install.html \
    benchmarks.html \
    configure.html \
    configure/quick_start.html \
    configure/command_options.html \
    configure/syntax_and_structure.html \
    configure/base_directives.html \
    configure/compress_directives.html \
    configure/http1_directives.html \
    configure/http2_directives.html \
    configure/access_log_directives.html \
    configure/errordoc_directives.html \
    configure/expires_directives.html \
    configure/fastcgi_directives.html \
    configure/file_directives.html \
    configure/headers_directives.html \
    configure/mruby_directives.html \
    configure/proxy_directives.html \
    configure/redirect_directives.html \
    configure/reproxy_directives.html \
    configure/server_timing_directives.html \
    configure/status_directives.html \
    configure/throttle_response_directives.html \
    configure/basic_auth.html \
    configure/cgi.html \
    configure/mruby.html \
    configure/dos_detection.html \
    configure/access_control.html \
    faq.html \

MAN = workdir/configure/quick_start.man \
      workdir/configure/syntax_and_structure.man \
      workdir/configure/base_directives.man \
      workdir/configure/compress_directives.man \
      workdir/configure/http1_directives.man \
      workdir/configure/http2_directives.man \
      workdir/configure/access_log_directives.man \
      workdir/configure/errordoc_directives.man \
      workdir/configure/expires_directives.man \
      workdir/configure/fastcgi_directives.man \
      workdir/configure/file_directives.man \
      workdir/configure/headers_directives.man \
      workdir/configure/mruby_directives.man \
      workdir/configure/proxy_directives.man \
      workdir/configure/redirect_directives.man \
      workdir/configure/reproxy_directives.man \
      workdir/configure/status_directives.man \
      workdir/configure/throttle_response_directives.man \
      workdir/configure/basic_auth.man \
      workdir/configure/cgi.man \
      workdir/configure/mruby.man \
      workdir/configure/dos_detection.man \
      workdir/configure/access_control.man

%.html: %.mt snippets/directive.mt snippets/wrapper.mt
	../misc/makedoc.pl $< $@

workdir/%.man: %.mt man-snippets/h2o.conf.5/directive.mt man-snippets/h2o.conf.5/header man-snippets/h2o.conf.5/mruby_method.mt man-snippets/h2o.conf.5/wrapper.mt
	../misc/makeman.pl $< $@

all: mkdir html search/searchindex.js manpage

mkdir:
	mkdir -p doc/configure

html: $(OUTPUT)

manpage: $(MAN)
	cat $(VPATH)/man-snippets/h2o.conf.5/header $(MAN) > h2o.conf.5
	( cat $(VPATH)/man-snippets/h2o.8/header \
	      $(VPATH)/man-snippets/h2o.8/description ; \
	  $(BINARY_DIR)/h2o --help | ../misc/cli2man.pl ; \
	  cat $(VPATH)/man-snippets/h2o.8/footer ) > h2o.8

search/searchindex.js: html
	../misc/oktavia/bin/oktavia-mkindex $(patsubst %,-i %,$(OUTPUT)) -m html -u h2 -c 10 -t js -s english

publish: all
	@if [ -z "$$PUBLISH" ] ; then \
		echo "environment variable PUBLISH not set" >&2 ; \
		exit 1; \
	fi
	tar cf - `git ls-files` | (cd $$PUBLISH && tar xf -)

clean:
	rm -f $(OUTPUT) $(MAN) search/searchindex.js

.PHONY: mkdir html publish publish-check do-publish manpage
