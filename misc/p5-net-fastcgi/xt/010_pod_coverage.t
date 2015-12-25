#!perl

use strict;
use warnings;

use Test::More;

BEGIN {
    eval 'use Test::Pod::Coverage';

    if ($@) {
        plan skip_all => 'Needs Test::Pod::Coverage';
    }
}

my @modules = sort grep { !/::(?:PP|XS)$/ } all_modules();

plan tests => scalar(@modules);

foreach my $module ( @modules ) {
    my $params = {};

    if ( $module =~ /^Net::FastCGI::Protocol$/ ) {
        $params->{coverage_class} = 'Pod::Coverage::ExportOnly';
    }

    pod_coverage_ok( $module, $params );
}

