use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

subtest "trailing HEADERS" => sub {
    my $doit = sub {
        my ($proto, $opts, $port) = @_;
        my $resp = `nghttp $opts -M 1 -m 3 -H ':method: GET' -d /dev/null --trailer 'foo: bar' '$proto://127.0.0.1:$port/'`;
        is $resp, "hello\n" x 3, $proto;
    };
    $doit->("http", "", $server->{port});
    $doit->("https", "", $server->{tls_port});
};

subtest "trailing HEADERS with CONTINUATION" => sub {
    my $doit = sub {
        my ($proto, $opts, $port) = @_;
        my $cmd = "nghttp $opts -M 1 -m 3 -H ':method: GET' -d /dev/null";
        $cmd .= join "", map {
            " --trailer 'foo$_: 0123456789abcdef:$_'"
        } 1..1000;
        $cmd .= " '$proto://127.0.0.1:$port/'";
        my $resp = `$cmd`;
        is $resp, "hello\n" x 3, $proto;
    };
    $doit->("http", "", $server->{port});
    $doit->("https", "", $server->{tls_port});
};

done_testing;
