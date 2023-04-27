#! /usr/bin/env perl

use strict;
use warnings;
use File::Temp qw(tempdir);
use POSIX ":sys_wait_h";
use Test::More;

$ENV{BINARY_DIR} ||= ".";
my $cli = "$ENV{BINARY_DIR}/cli";
my $tempdir = tempdir(CLEANUP => 1);

plan skip_all => "skipping live tests (setenv LIVE_TESTS=1 to run them)"
    unless $ENV{LIVE_TESTS};

subtest "crypto.cloudflare.com" => sub {
    my $req_fn = "$tempdir/req";
    my $ech_config_fn = "$tempdir/echconfiglist";
    my $fetch = sub {
        open my $fh, "$cli -I -E $ech_config_fn crypto.cloudflare.com 443 < $req_fn |"
            or die "failed to open $cli to connect to crypto.cloudflare.com";
        join "", <$fh>;
    };

    { # build request as a temporary file
        open my $fh, ">", $req_fn
            or die "failed to create file:$req_fn:$!";
        print $fh "GET /cdn-cgi/trace HTTP/1.0\r\nHost: crypto.cloudflare.com\r\n\r\n";
        close $fh;
    }

    { # create empty ECHConfigList file so as to grease and obtain true config
        open my $fh, ">", $ech_config_fn
            or die "failed to create file:$ech_config_fn:$!";
        close $fh;
    }

    my $resp = $fetch->();
    like $resp, qr/^sni=plaintext$/m, "response to grease";
    isnt +(stat $req_fn)[7], 0, "echconfiglist is non-empty";

    $resp = $fetch->();
    like $resp, qr/^sni=encrypted$/m, "response to innerCH";
};

done_testing;
