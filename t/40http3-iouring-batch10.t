exec $^X, "t/40http3/test.pl", "--batch-size=10";
die "failed to invoke $^X t/40http3/test.pl:$!";
