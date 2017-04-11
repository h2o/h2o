use strict;
use warnings;
use Test::More;
use Net::EmptyPort qw(check_port empty_port);
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
    unlike $resp, qr{\nserver}, "server unset";
};

my $upstream_port = empty_port();

my $upstream = spawn_server(
	argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
	is_ready =>  sub {
		check_port($upstream_port);
	},
);

subtest "preserve server header" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
server-name: not-sent
send-server-name: preserve
EOT
    my $resp = `curl --silent -Hserver:this-one-is-sent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/echo-server-header 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
    like $resp, qr{\nserver: this-one-is-sent}i, "server: set to expected value";
    unlike $resp, qr{\nserver: not-sent}i, "server: not set to the internal value";
};

subtest "do not preserve server header" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
server-name: sent-this-time
send-server-name: ON
EOT
    my $resp = `curl --silent -Hserver:this-one-is-not-sent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/echo-server-header 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
    like $resp, qr{\nserver: sent-this-time}i, "server: set to the internal value";
    unlike $resp, qr{\nserver: this-one-is-not-sent}i, "server: not set to the backend value";
};

done_testing();
