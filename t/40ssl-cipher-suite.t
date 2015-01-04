use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Scope::Guard qw(scope_guard);
use Test::More;
use t::Util;

my $port = empty_port();

# spawn server that only accepts RC4-MD5
my ($conffh, $conffn) = tempfile();
print $conffh <<"EOT";
listen:
  host: 127.0.0.1
  port: $port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    cipher-suite: RC4-MD5
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

# connect to the server with RC4-SHA1 as the first choice, and check that RC4-MD5 was selected
my $log = `openssl s_client -cipher RC4-SHA:RC4-MD5 -host 127.0.0.1 -port $port < /dev/null 2>&1`;
like $log, qr/^\s*Cipher\s*:\s*RC4-MD5\s*$/m;

done_testing;
