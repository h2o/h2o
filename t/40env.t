use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

subtest "fastcgi" => sub {
    my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
  unsetenv:
    - "foo"
setenv:
  "global": 123
hosts:
  default:
    setenv:
      "host": 234
    paths:
      "/":
        setenv:
          "path": 345
          "foo": "abc"
        file.dir: @{[ DOC_ROOT ]}
      "/unset":
        unsetenv: "host"
        file.dir: @{[ DOC_ROOT ]}
EOT
    subtest "basic" => sub {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/printenv.cgi`;
            like $resp, qr{^global:123$}m;
            like $resp, qr{^host:234$}m;
            like $resp, qr{^path:345$}m;
            unlike $resp, qr{^foo:}m;
        });
    };
    subtest "unsetenv" => sub {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/unset/printenv.cgi`;
            like $resp, qr{^global:123$}m;
            unlike $resp, qr{^host:}m;
            unlike $resp, qr{^path:}m;
            unlike $resp, qr{^foo:}m;
        });
    };
};

subtest "mruby" => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      "/":
        setenv:
          foo: 123
        mruby.handler: |
          Proc.new do |env|
            [
              200,
              {"content-type" => "text/plain; charset=utf-8"},
              [(env.map {|k, v| k + ":" + String(v) + "\n"}).join]
            ]
          end
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
        like $resp, qr{^foo:123$}m;
    });
};

done_testing();
