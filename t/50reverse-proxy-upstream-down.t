use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub doit {
    my $persistent = shift;
    my $upstream_port = safe_empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.timeout.io: 2000
@{[ $persistent ? "" : "proxy.timeout.keepalive: 0" ]}
EOT
    my $port = $server->{port};
    my $res = `curl --max-time 5 --silent --dump-header /dev/stderr http://127.0.0.1:$port/ 2>&1 > /dev/null`;
    like $res, qr{^HTTP/1\.1 502 }, "502 response on upstream error";
    safe_empty_port_release($upstream_port);
};

subtest 'non-persistent' => sub {
    doit(0);
};

subtest 'persistent' => sub {
    doit(1);
};

done_testing();
