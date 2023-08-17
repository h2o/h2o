#!perl
use strict;
use warnings FATAL => "all";
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;
plan skip_all => 'capabilities(7) support is off'
    unless server_features()->{capabilities};

run_as_root();

my $h2o = spawn_h2o({
    user => scalar(getpwuid($ENV{SUDO_UID})),
    conf => << "EOT",
capabilities:
  - CAP_NET_ADMIN
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

my ($headers, $content) = run_prog("$client_prog http://127.0.0.1:$h2o->{port}/");
like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1.1 200";
is $content, "hello\n", "content";

done_testing;
