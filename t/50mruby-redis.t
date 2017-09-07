use strict;
use warnings;
use IO::Socket::INET;
use JSON;
use Net::EmptyPort qw(check_port empty_port);
use Time::HiRes;
use Test::More;
use t::Util;

plan skip_all => "could not find redis-server"
    unless prog_exists("redis-server");
plan skip_all => "could not find redis-cli"
    unless prog_exists("redis-cli");

my $REPLY_HEADER = 'x-redis-reply';

subtest 'oneshot' => sub {
    subtest 'basic' => sub {
        my ($tester, $guard) = setup(<<"EOT");
              proc {|env|
                redis.set('k1', 1)
                redis.incrby('k1', 109)
                reply = redis.get('k1').join
                [200, { '$REPLY_HEADER' => reply }, []]
              }
EOT
        my ($status, $headers) = $tester->();
        is $status, 200;
        is $headers->{$REPLY_HEADER}, '110';
    };

    subtest 'prefetch' => sub {
        my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 'prefetched').join
              reply = redis.get('k1').join
              proc {|env|
                [200, { '$REPLY_HEADER' => reply }, []]
              }
EOT
        my ($status, $headers) = $tester->();
        is $status, 200;
        is $headers->{$REPLY_HEADER}, 'prefetched';
    };

    subtest 'cache' => sub {
        my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 'cached').join
              reply = nil
              called = false
              proc {|env|
                reply ||= begin
                  raise "called multiple time" if called
                  called = true
                  redis.get('k1').join
                end
                [200, { '$REPLY_HEADER' => reply }, []]
              }
EOT
        my ($status, $headers) = $tester->();
        is $status, 200;
        is $headers->{$REPLY_HEADER}, 'cached';
    };

    subtest 'command error' => sub {
        my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 1).join
              proc {|env|
                begin
                  redis.lpush('k1', 1).join
                rescue H2O::Redis::CommandError => e
                  [503, { '$REPLY_HEADER' => e.message }, []]
                else
                  [200, {}, []]
                end
              }
EOT
        my ($status, $headers) = $tester->();
        is $status, 503;
        is $headers->{$REPLY_HEADER}, 'WRONGTYPE Operation against a key holding the wrong kind of value (command: LPUSH k1 1)';
    };

    subtest 'connection error' => sub {
        my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 'hoge').join
              proc {|env|
                begin
                  reply = redis.get('k1').join
                rescue H2O::Redis::ConnectionError => e
                  [503, {}, []]
                else
                  [200, { '$REPLY_HEADER' => reply }, []]
                end
              }
EOT
        my ($status, $headers);

        ($status, $headers) = $tester->();
        is $status, 200;
        is $headers->{$REPLY_HEADER}, 'hoge';

        undef $guard->{redis}; # shutdown redis-server

        ($status, $headers) = $tester->();
        is $status, 503;
    };

    subtest 'transaction' => sub {

        subtest 'multi' => sub {
            my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 1).join
              proc {|env|
                multi_reply = redis.multi {
                  redis.incr('k1')
                  redis.incr('k1')
                  redis.incr('k1')
                }.join
                reply = redis.get('k1').join
                [200, {}, [JSON.generate([reply, multi_reply])]]
              }
EOT
            my ($status, $headers, $body) = $tester->();
            is $status, 200;
            is_deeply decode_json($body), [4, [2, 3, 4]];
        };

        subtest 'discard automaticaly when transaction failed' => sub {
            my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 1).join
              proc {|env|
                multi_reply = begin
                  redis.multi {
                    redis.incr('k1')
                    redis.lpush('k1', 'funny thing') # invalid command
                    redis.incr('k1')
                  }.join
                rescue H2O::Redis::CommandError => e
                end
                reply = redis.get('k1').join
                [200, {}, [JSON.generate([reply, multi_reply])]]
              }
EOT
            my ($status, $headers, $body) = $tester->();
            is $status, 200;
            is_deeply decode_json($body), [3, undef];
        };

        subtest 'watch' => sub {

            subtest 'success' => sub {
                my ($tester, $guard) = setup(<<"EOT");
              redis.set('k1', 1).join
              proc {|env|
                redis.watch('k1') {
                  val = redis.get('k1').join.to_i
                  redis.multi {
                    redis.set('k1', val + 1)
                  }
                }
                reply = redis.get('k1').join
                [200, {}, [reply]]
              }
EOT
                my ($status, $headers, $body) = $tester->();
                is $status, 200;
                is $body, 2;
            };

            subtest 'failure' => sub {
                my ($tester, $guard) = setup(sub {
                    my ($redis_port) = @_;
                    <<"EOT";
              another_redis = H2O::Redis.new(:host => '127.0.0.1', :port => $redis_port)
              redis.set('k1', 1).join
              proc {|env|
                redis.watch('k1') {
                  val = redis.get('k1').join.to_i
                  another_redis.set('k1', 110).join
                  redis.multi {
                    redis.set('k1', val + 1)
                  }.join
                }
                [200, {}, []]
              }
EOT
                });
                my ($status, $headers, $body) = $tester->();
                is $status, 500;
            };

        };

    };

};

# TODO: add streaming command tests when those are implemented

done_testing;

sub setup {
    my ($conf_code, $opts) = @_;
    $opts ||= +{};
    my $redis_port = empty_port();
    my $redis = $opts->{no_redis} ? undef : spawn_server(
        argv     => [ qw(redis-server --port), $redis_port ],
        is_ready => sub { check_port($redis_port) },
    );
    $conf_code = $conf_code->($redis_port) if ref($conf_code) eq 'CODE';
    
    my $conf = <<"EOT";
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          redis = H2O::Redis.new(:host => '127.0.0.1', :port => $redis_port)
$conf_code
EOT
    my $server = spawn_h2o($conf);
    my $tester = sub {
        my %args = @_;
        my $url = "http://127.0.0.1:$server->{port}/";
        $url .= '?' . $args{query_string} if $args{query_string};

        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr $url");
        my $status;

        # parse status and convert headers to hash
        my @header_lines = split(/\n/, $headers);
        $_ =~ s/^\s+|\s+$//g for @header_lines;
        $header_lines[0] =~ qr!HTTP/(?:[\d.]+) (\d+)! or die "status line is invalid : $header_lines[0]";
        $status = $1;
        shift(@header_lines);
        pop(@header_lines);
        $headers = +{ map { split(/\s*:\s*/, $_, 2) } @header_lines };

        return ($status, $headers, $body);
    };
    my $redis_client = sub {
        my @commands = @_;
        `redis-cli -p $redis_port @{[join(' ', @commands)]}`;
    };
    return ($tester, { redis => $redis, server => $server }, $redis_client)
}

