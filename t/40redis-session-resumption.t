use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::SSL;
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;

plan skip_all => "could not find redis-server"
    unless prog_exists("redis-server");
plan skip_all => "could not find redis-cli"
    unless prog_exists("redis-cli");

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

sub spawn_redis {
    # start redis
    my $redis_port = empty_port({ host => '0.0.0.0' });
    my ($redis_guard, $pid) = spawn_server(
        argv     => [ qw(redis-server --loglevel warning --port), $redis_port ],
        is_ready => sub {
            check_port($redis_port);
        },
    );
    return { guard => $redis_guard, port => $redis_port, pid => $pid };
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

subtest 'load test' => sub {
    my $CONCURRENCY = 10;

    my $redis = spawn_redis();
    my $server = spawn_h2o(<< "EOT");
ssl-session-resumption:
  lifetime: 3
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

    my %pids;
    my $is_redis_director = 1;
    for my $i (1..$CONCURRENCY) {
        my $pid = fork;
        die "fork failed: $!" unless defined($pid);
        if ($pid) {
            $pids{$pid} = 1;
            $is_redis_director = 0;
        } else {

            my $session_cache = IO::Socket::SSL::Session_Cache->new(1);
            my @scenario = (
                +{
                    count => 100,
                },
                +{
                    setup => sub {
                        # clear session cache
                        $session_cache = IO::Socket::SSL::Session_Cache->new(1);
                    },
                    count => 100,
                },
                +{
                    setup => sub {
                        # set invalid session id
                        $session_cache->{"127.0.0.1:$redis->{port}"}->{session} = "$$:invalid_session_id";
                    },
                    count => 100,
                },
                +{
                    setup => sub {
                        # flushall
                        if ($is_redis_director) {
                            system("redis-cli -h 127.0.0.1 -p $redis->{port} flushall");
                        } else {
                            sleep 0.1;
                        }
                    },
                    count => 100,
                },
                +{
                    setup => sub {
                        # terminate redis
                        if ($is_redis_director) {
                            kill 'KILL', $redis->{pid};
                        } else {
                            sleep 0.1;
                        }
                    },
                    count => 100,
                },
            );
            for my $s (@scenario) {
                $s->{setup}->() if $s->{setup};
                for (1..$s->{count}) {
                    my $client = IO::Socket::SSL->new(
                        PeerHost => '127.0.0.1',
                        PeerPort => $server->{tls_port},
                        SSL_verify_mode => 0,
                        SSL_session_cache => $session_cache,
                    ) or exit 1;
                    $client->syswrite("GET / HTTP/1.1\r\n\r\n");
                    $client->sysread(my $buf, 4096);
                    $client->close(SSL_no_shutdown => 1);
                    exit 2 unless $buf =~ m{200 OK};
                }
            }
            exit;
        }
    }
    while (%pids) {
        my $kid = waitpid(-1, WNOHANG);
        if ($kid) {
            is($? >> 8, 0, 'exit code is 0');
            delete $pids{$kid};
        } else {
            sleep 0.1;
        }
    }

    # finally, check that the server process is alive
    ok(kill(0, $server->{pid}), 'server is alive');
};

done_testing;

