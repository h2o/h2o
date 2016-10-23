use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => "could not find redis-server"
    unless prog_exists("redis-server");

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

sub spawn_redis {
    # start redis
    my $redis_port = empty_port();
    my $redis_guard = spawn_server(
        argv     => [ qw(redis-server --port), $redis_port ],
        is_ready => sub {
            check_port($redis_port);
        },
    );
    return { guard => $redis_guard, port => $redis_port };
}

sub test {
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my ($server, $client_opts, $expected) = @_;
    $expected = [ $expected ] unless ref $expected eq 'ARRAY';
    for my $exp (@$expected) {
        my $lines = do {
            open my $fh, "-|", "openssl s_client -no_ticket $client_opts -connect 127.0.0.1:$server->{tls_port} 2>&1 < /dev/null"
                or die "failed to open pipe:$!";
            local $/;
            <$fh>;
        };
        if (ok $lines !~ qr/ssl handshake failure/, 'ssl handshake failure') {
            $lines =~ m{---\n(New|Reused),}s
                or die "failed to parse the output of s_client:{{{$lines}}}";
            is $1, $exp;
        }
    }
}

subtest 'basic' => sub {
    my $tempdir = tempdir(CLEANUP => 1);
    my $redis = spawn_redis();
    my $conf = << "EOT";
num-threads: 1
ssl-session-resumption:
  mode: cache
  cache-store: redis
  redis:
    host: 127.0.0.1
    port: $redis->{port}
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    test(spawn_h2o($conf), "-sess_out $tempdir/session", "New");
    test(spawn_h2o($conf), "-sess_in $tempdir/session", ["New", "Reused"]); # At the first request, redis connection hasn't been established
};

subtest "non-reachable redis server" => sub {
    my $tempdir = tempdir(CLEANUP => 1);
    # 192.0.2.0/24 is documentation address block, so not reachable
    # see: https://tools.ietf.org/html/rfc5737
    my $conf = << "EOT";
num-threads: 1
handshake-timeout: 1
ssl-session-resumption:
  mode: cache
  cache-store: redis
  redis:
    host: 192.0.2.0
    port: 6379
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    test(spawn_h2o($conf), "-sess_out $tempdir/session", "New");
    test(spawn_h2o($conf), "-sess_in $tempdir/session", ["New", "New"]);
};

done_testing;

