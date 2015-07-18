use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub fetch {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
$extra_conf
EOT
    return `curl --silent /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1`;
}


my $resp = fetch(<< 'EOT');
        mruby.handler_path: t/50mruby/hello.rb
EOT
is $resp, "hello from h2o_mruby\n", "resoponse body from mruby";

$resp = fetch(<< 'EOT');
        mruby.handler_path: t/50mruby/max_header.rb
EOT
is $resp, "100", "H2O.max_headers method";

done_testing();
