use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'nc not found'
    unless prog_exists('nc');

my @ports = empty_ports(3);

my $tempdir = tempdir(CLEANUP => 1);

{ # create configuration file
    open my $fh, ">", "$tempdir/h2o.conf"
        or die "failed to create file:$tempdir/h2o.conf:$!";
    print $fh <<"EOT";
hosts:
  host1: \&default
    listen: $ports[0]
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [env["SERVER_NAME"]]]
          end
  host2:
    listen: $ports[1]
    <<: *default
  host3:
    <<: *default
    listen: $ports[2]
EOT
};

my $guard = spawn_server(
    argv     => [ bindir() . "/h2o", "-c", "$tempdir/h2o.conf" ],
    is_ready => sub {
        for (@ports) {
            return unless check_port($_);
        }
        return 1;
    },
);

subtest "port1" => sub {
    subtest "no-host" => sub {
        my $resp = `(echo "GET / HTTP/1.0"; echo) | nc 127.0.0.1 $ports[0] 2>&1`;
        like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;
        like $resp, qr{\r\n\r\nhost1$}s;
    };
    subtest "host=host2" => sub {
        my $resp = `(echo "GET / HTTP/1.0"; echo "Host: host2"; echo) | nc 127.0.0.1 $ports[0] 2>&1`;
        like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;
        like $resp, qr{\r\n\r\nhost2$}s;
    };
    subtest "host=host3" => sub {
        # host3 is not listening on the default port
        my $resp = `(echo "GET / HTTP/1.0"; echo) | nc 127.0.0.1 $ports[0] 2>&1`;
        like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;
        like $resp, qr{\r\n\r\nhost1$}s;
    };
};

subtest "port2" => sub {
    my $resp = `(echo "GET / HTTP/1.0"; echo) | nc 127.0.0.1 $ports[1] 2>&1`;
    like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;
    like $resp, qr{\r\n\r\nhost2$}s;
};

subtest "port3" => sub {
    my $resp = `(echo "GET / HTTP/1.0"; echo) | nc 127.0.0.1 $ports[2] 2>&1`;
    like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;
    like $resp, qr{\r\n\r\nhost3$}s;
};

done_testing;
