use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub doit {
    my $persistent = shift;
    my $upstream_port = empty_port();
    my $server = spawn_h2o({ prefix => [ qw(valgrind --tool=memcheck --) ], conf => << "EOT" });
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
@{[ $persistent ? "" : "proxy.timeout.keepalive: 2000" ]}
EOT
    my $port = $server->{port};
    my $res = `curl --max-time 5 --silent --dump-header /dev/stderr http://127.0.0.1:$port/ 2>&1 > /dev/null`;
    like $res, qr{^HTTP/1\.1 502 }, "502 response on upstream error";
};

subtest 'non-persistent' => sub {
    doit(0);
};

subtest 'persistent' => sub {
    doit(1);
};

done_testing();
