use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Scope::Guard qw(scope_guard);
use Test::More;
use t::Util;

my $port = empty_port();

# spawn server that only accepts AES128-SHA
my ($conffh, $conffn) = tempfile(UNLINK => 1);
print $conffh <<"EOT";
listen:
  host: 127.0.0.1
  port: $port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    cipher-suite: AES128-SHA
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
my ($guard, $pid) = spawn_server(
    argv     => [ bindir() . "/h2o", "-c", $conffn ],
    is_ready => sub {
        check_port($port);
    },
);

# connect to the server with AES256-SHA as the first choice, and check that AES128-SHA was selected
my $log = `openssl s_client -cipher AES256-SHA:AES128-SHA -host 127.0.0.1 -port $port < /dev/null 2>&1`;
like $log, qr/^\s*Cipher\s*:\s*AES128-SHA\s*$/m;

done_testing;
