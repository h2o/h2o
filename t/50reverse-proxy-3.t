$0 =~ /-([0-9]+)\.t$/s
    or die "failed to extract mode";
exec $^X, "t/50reverse-proxy/test.pl", "--mode=$1";
die "failed to invoke $^X t/50reverse-proxy/test.pl:$!";
