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

subtest 'db option' => sub {
    my ($redis, $redis_port) = spawn_redis();
    my $conf = <<"EOT";
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          redis = H2O::Redis.new(:host => '127.0.0.1', :port => $redis_port, :db => 1)
          proc {|env|
            db = env['QUERY_STRING']
            unless db.empty?
              redis.db = db.to_i
            end
            value = redis.incr('hoge').join
            [200, {}, [value]]
          }
EOT
    my $server = spawn_h2o($conf);
    my $body;
    (undef, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}");
    is($body, '1');
    (undef, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}?2");
    is($body, '1');
    (undef, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}?1");
    is($body, '2');
};

subtest 'streaming' => sub {
    subtest 'basic' => sub {
        my $confmap = +{
            '/' => <<"EOT",
          channel = redis.subscribe('chan1').join
          proc {|env|
            begin
              reply = channel.shift
              [200, { '$REPLY_HEADER' => reply.join(':') }, []]
            rescue H2O::Redis::ConnectionError => e
              [503, {}, []]
            end
          }
EOT
            '/publish' => <<"EOT",
          proc {|env|
            channel, message = env['QUERY_STRING'].split(':')
            redis.publish(channel, message)
            [200, {}, []]
          }
EOT
            '/concat-all' => <<"EOT",
          \$unsubscribe_redis = redis # to unsubscribe later
          channel = redis.subscribe('chan2').join
          proc {|env|
            messages = []
            loop while channel.shift {|channel, message| messages << message }
            [200, { '$REPLY_HEADER' => messages.join(':') }, []]
          }
EOT
            '/unsubscribe' => <<"EOT",
          proc {|env|
            raise 'oops' if \$unsubscribe_redis.nil?
            \$unsubscribe_redis.unsubscribe('chan2')
            [200, {}, []]
          }
EOT
        };

        subtest 'publish before' => sub {
            my ($tester, $guard) = setup($confmap);
            $tester->(path => '/publish?chan1:FOO');
            $tester->(path => '/publish?chan1:BAR');

            my ($status, $headers);
            ($status, $headers) = $tester->();
            is $status, 200;
            is $headers->{$REPLY_HEADER}, 'chan1:FOO';

            ($status, $headers) = $tester->();
            is $status, 200;
            is $headers->{$REPLY_HEADER}, 'chan1:BAR';
        };

        subtest 'publish after' => sub {
            my ($tester, $guard) = setup($confmap);

            unless (fork) {
              sleep 1;
              $tester->(path => '/publish?chan1:FOO');
              exit;
            }

            my ($status, $headers);
            my $start = Time::HiRes::time;
            ($status, $headers) = $tester->();
            my $duration = Time::HiRes::time - $start;
            is $status, 200;
            is $headers->{$REPLY_HEADER}, 'chan1:FOO';
            cmp_ok($duration, '>', 1, 'block until publish');
        };

        subtest 'unsubscribe' => sub {
            my ($tester, $guard) = setup($confmap);

            $tester->(path => '/publish?chan2:msg1');
            unless (fork) {
              sleep 1;
              $tester->(path => '/publish?chan2:msg2');
              sleep 1;
              $tester->(path => '/unsubscribe');
              exit;
            }

            my ($status, $headers);
            my $start = Time::HiRes::time;
            ($status, $headers) = $tester->(path => '/concat-all');
            my $duration = Time::HiRes::time - $start;
            is $status, 200;
            is $headers->{$REPLY_HEADER}, 'msg1:msg2';
            cmp_ok($duration, '>', 2, 'block until unsubscribe');
        };

        subtest 'connection error' => sub {
            my ($tester, $guard) = setup($confmap);

            local $SIG{ALRM} = sub {
                undef $guard->{redis}; # shutdown redis-server
            };

            my ($status, $headers);
            alarm(1);
            my $start = Time::HiRes::time;
            ($status, $headers) = $tester->();
            my $duration = Time::HiRes::time - $start;
            alarm(0);
            is $status, 503;
            cmp_ok($duration, '>', 1, 'block until shutdown');

            ($status, $headers) = $tester->();
            is $status, 503, 'raise same error immediately on same subscription';
        };
    };
};

done_testing;

sub spawn_redis {
    my ($opts) = @_;
    my $redis_port = empty_port();
    my $redis = $opts->{no_redis} ? undef : spawn_server(
        argv     => [ qw(redis-server --port), $redis_port ],
        is_ready => sub { check_port($redis_port) },
    );
    return ($redis, $redis_port);
}

sub setup {
    my ($confmap, $opts) = @_;
    $opts ||= +{};
    my ($redis, $redis_port) = spawn_redis($opts);
    $confmap = $confmap->($redis_port) if ref($confmap) eq 'CODE';
    unless (ref($confmap)) {
      $confmap = +{ '/' => $confmap };
    }
    
    my $conf = <<"EOT";
num-threads: 1
hosts:
  default:
    paths:
EOT
    for my $path (keys %$confmap) {
      my $code = $confmap->{$path};
      $conf .= <<"EOT";
      $path:
        mruby.handler: |
          redis = H2O::Redis.new(:host => '127.0.0.1', :port => $redis_port)
$code
EOT
    }

    my $server = spawn_h2o($conf);
    my $tester = sub {
        local $Test::Builder::Level = $Test::Builder::Level + 1;
        my %args = @_;
        my $url = "http://127.0.0.1:$server->{port}@{[ $args{path} || '/' ]}";
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

