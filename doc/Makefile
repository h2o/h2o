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
    configure/status_directives.html \
    configure/throttle_response_directives.html \
    configure/basic_auth.html \
    configure/cgi.html \
    configure/mruby.html \
    configure/dos_detection.html \
    configure/access_control.html \
    faq.html \

%.html: %.mt snippets/directive.mt snippets/wrapper.mt
	../misc/makedoc.pl $< $@

all: mkdir html search/searchindex.js

mkdir:
	mkdir -p doc/configure

html: $(OUTPUT)

search/searchindex.js: html
	../misc/oktavia/bin/oktavia-mkindex $(patsubst %,-i %,$(OUTPUT)) -m html -u h2 -c 10 -t js -s english

publish: all
	@if [ -z "$$PUBLISH" ] ; then \
		echo "environment variable PUBLISH not set" >&2 ; \
		exit 1; \
	fi
	tar cf - `git ls-files` | (cd $$PUBLISH && tar xf -)

clean:
	rm -f $(OUTPUT) search/searchindex.js

.PHONY: mkdir html publish publish-check do-publish
