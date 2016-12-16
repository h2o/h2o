use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "valid configuration" => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler:
          acl { respond(402) }
EOT
    my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 402}s;
};

subtest "invalid configuration 1" => sub {
    throws_ok sub {
        spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          acl { respond(403) }
          acl { respond(200) }
EOT
    }, qr/server failed to start/, 'acl cannot be called more than once';
};

subtest "invalid configuration 2" => sub {
    throws_ok sub {
        spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          acl { respond(403) }
          proc {|env| [200, {}, []]}
EOT
    }, qr/server failed to start/, 'acl configuration is ignored';
};

done_testing();
