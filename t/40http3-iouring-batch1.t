exec $^X, "t/40http3/test.pl", "--batch-size=1";
die "failed to invoke $^X t/40http3/test.pl:$!";
