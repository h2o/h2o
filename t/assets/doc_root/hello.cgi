#! /usr/bin/env perl

use strict;
use warnings;

print "Content-Type: text/plain; charset=utf-8\r\n\r\n";

print "Hello ", $ENV{PATH_INFO} ? substr $ENV{PATH_INFO}, 1 : "unknown";
