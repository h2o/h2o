use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

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
