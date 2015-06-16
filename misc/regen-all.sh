#! /bin/sh

misc/tokens.pl || exit 1
misc/picotemplate/picotemplate.pl --conf misc/picotemplate-conf.pl lib/handler/file/_templates.c.h || exit 1
misc/clang-format-all.sh || exit 1
(cd misc/p5-Server-Starter && fatpack-simple --shebang '#! /bin/sh'$'\n''exec perl -x $0 "$@"'$'\n''#! perl' -o ../../share/h2o/start_server script/start_server) || exit 1
