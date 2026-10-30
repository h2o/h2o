exec $^X, "t/40http3/test.pl", "--multithread=0", "--qpack-server-conf", "  quic:\n    qpack-encoder-refine: OFF\n";
die "failed to invoke $^X t/40http3/test.pl:$!";
