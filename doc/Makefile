VPATH=../srcdoc
OUTPUT=index.html install.html configure.html faq.html
PUBLISH_REPO=git@github.com:h2o/h2o.github.io.git
COMMIT=$(shell git rev-parse --short HEAD)

%.html: %.mt
	../misc/makedoc.pl $< $@

all: html search/searchindex.js

html: $(OUTPUT)

search/searchindex.js: html
	../misc/oktavia/bin/oktavia-mkindex $(patsubst %,-i %,$(OUTPUT)) -m html -u h2 -c 10 -t js -s english

publish: all
	@DIRTY=`git status | grep 'Changes .* commit'` ; \
	if [ -n "$$DIRTY" ] ; then \
		echo "uncommitted changes exist; aborting" >&2 ; \
		exit 1 ; \
	fi
	$(MAKE) do-publish

do-publish:
	../misc/git-pushdir/git-pushdir -m "pushing docs of $(COMMIT)" "$(PUBLISH_REPO)"

clean:
	rm -f $(OUTPUT) search/searchindex.js

.PHONY: html publish do-publish
