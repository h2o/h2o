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
      "/this-is-not-root":
        file.dir: @{[DOC_ROOT]}
EOT

sub doit {
    my ($proto, $port) = @_;
    my $resp = `nghttp -d @{[DOC_ROOT]}/halfdome.jpg $proto://127.0.0.1:$port/`;
    is $resp, "not found", $proto;
}

doit('http', $server->{port});
doit('https', $server->{tls_port});

done_testing();
