use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "h2o is not built with libaegis"
    unless server_features()->{libaegis};

my $port = empty_port();

# just make sure that the server spawns correctly
my $server = spawn_h2o_raw(<< "EOT");
listen:
  port: $port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    cipher-suite-tls1.3: [ TLS_AEGIS_128L_SHA256 ]
hosts:
  default:
    paths: /
      file.dir: t/assets/doc_root
EOT

undef $server;

done_testing;
