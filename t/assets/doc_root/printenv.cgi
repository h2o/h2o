#! /bin/sh
exec ${H2O_PERL:-perl} -x $0 "$@"
#! perl

print "content-type: text/plain; charset=utf-8\r\n\r\n";

for my $k (sort keys %ENV) {
  print "$k:$ENV{$k}\n";
}
