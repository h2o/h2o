use strict;
use warnings;

# t/50webtransport-moq-qmux.t, with the relay listening on a Unix socket (`url: unix:<path>` of webtransport.moq)
our $RELAY_UNIX = 1;
do "./t/50webtransport-moq-qmux.t";
die $@ if $@;
