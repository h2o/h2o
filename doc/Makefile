VPATH=../srcdoc
OUTPUT=index.html install.html configure.html libh2o.html faq.html

%.html: %.mt
	../misc/makedoc.pl $< $@

all: html src/searchindex.js

html: $(OUTPUT)

src/searchindex.js: html
	../misc/oktavia/bin/oktavia-mkindex $(patsubst %,-i %,$(OUTPUT)) -m html -u h2 -c 10 -t js -s english
	
clean:
	rm -f $(OUTPUT) search/searchindex.js

.PHONY: html search-index
