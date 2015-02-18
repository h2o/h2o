use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

# should return 502 in case of upstream error
subtest 'upstream-down' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    my $upstream_port = empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my $port = $server->{port};
    my $res = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$port/ 2>&1 > /dev/null`;
    like $res, qr{^HTTP/1\.1 502 }, "502 response on upstream error";
};

done_testing();
