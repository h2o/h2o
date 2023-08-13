use strict;
use warnings;
use utf8;
use File::Temp qw(tempfile);
use Path::Tiny;
use Time::HiRes qw(sleep);
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
    });
    $backend->{tls_port} = $backend_port;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:$backend->{tls_port}
EOT
    my $client_command = "/bin/echo -n 'aaaaaaaaaa' | " .
                         "nghttp -vn -H ':method: POST' --data '-' --trailer 'x-client-trailer: foo' " .
                         "'https://127.0.0.1:$server->{tls_port}/index.txt'";
    my $client_log = `$client_command`;
    like $client_log, qr/x-backend-trailer: bar/;

    $backend->{kill}->();
    my $backend_log = readline($backend->{stdout});
    # TODO: check if request trailers to be forwarded
    # like $backend_log, qr/x-client-trailer: foo/;
};

done_testing;

