use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "default server header" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
    like $resp, qr{^server: h2o/.*\r$}im, "h2o default Server: header found";
    is +(() = $resp =~ m{^server}img), 1, "header added only once";
};

subtest "alternate server header" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
server-name: h2oalternate
EOT

    my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
    like $resp, qr{^server: h2oalternate\r$}im, "alternate h2o Server: header found";
    is +(() = $resp =~ m{^server}img), 1, "header added only once";
};

subtest "no server header" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
server-name: h2oalternate
send-server-name: OFF
EOT
    my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
    unlike $resp, qr{^server}, "server unset";
};

done_testing();
