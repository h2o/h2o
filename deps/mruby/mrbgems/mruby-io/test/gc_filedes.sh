#!/bin/sh

ulimit -n 20
mruby -e '100.times { File.open "'$0'" }'
