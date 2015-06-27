exec(
    $^X,
    qw(t/50reverse-proxy/test.pl --h2o-keepalive=0 --starlet-keepalive=0 --starlet-force-chunked=1),
);
die "failed to invoke $^X t/50reverse-proxy/test.pl:$!";
