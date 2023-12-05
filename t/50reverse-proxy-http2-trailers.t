use strict;
use warnings;
use utf8;
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

subtest 'nghttp2 client and backend' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    plan skip_all => 'nghttpd not found'
        unless prog_exists('nghttpd');

    my ($backend_port) = empty_ports(1, { host => '0.0.0.0' });
    my $backend = spawn_forked(sub {
        exec('nghttpd', '-v', '--htdocs', DOC_ROOT,
             '--trailer', 'x-backend-trailer: bar',
             $backend_port, 'examples/h2o/server.key', 'examples/h2o/server.crt');
        die "failed to exec nghttpd: $?";
    });
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:$backend_port
EOT
    my $client_command = "/bin/echo -n 'aaaaaaaaaa' | " .
                         "nghttp -vn -H ':method: POST' --data '-' --trailer 'x-client-trailer: foo' " .
                         "'https://127.0.0.1:$server->{tls_port}/index.txt'";
    my $client_log = `$client_command`;
    like $client_log, qr/recv DATA frame.+x-backend-trailer: bar/s;

    # TODO: uncomment after þtps://github.com/h2o/h2o/pull/3241 gets merged
    # my ($backend_log) = $backend->{kill}->();
    # like $backend_log, qr/recv DATA frame.+x-client-trailer: foo/s;
};

done_testing;

