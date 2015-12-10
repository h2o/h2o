#! /usr/bin/env perl

use strict;
use warnings;
use CGI;

my $q = CGI->new;

print $q->header("text/plain; charset=utf-8");
print "Hello ", $q->param("name") || "unknown";

close STDOUT;
print STDERR "hello.cgi is shutting down\n";
