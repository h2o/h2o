use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'fixnum' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            ret = sleep(1)
            [200, {}, [ret]]
          }
EOT
    my $st = Time::HiRes::time;
    (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    my $rtt = Time::HiRes::time - $st;
    is $body, "1";
    cmp_ok $rtt, '>=', 1
};

subtest 'float' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            ret = sleep(0.5)
            [200, {}, [ret]]
          }
EOT
    my $st = Time::HiRes::time;
    (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    my $rtt = Time::HiRes::time - $st;
    is $body, "0";
    cmp_ok $rtt, '>=', 0.5 
};

subtest 'configuration phase' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          ret = sleep(0.2)
          proc {|env|
            [200, {}, [ret]]
          }
EOT
    (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $body, "0";
};

subtest 'parallel' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            sleep(1)
            [200, {}, ["hello"]]
          }
EOT
    my $pid = fork or do {
        (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        is $body, 'hello';
        exit;
    };
    (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $body, 'hello';
    waitpid($pid, 0);
};

subtest 'is it really non-blocking?' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /foo:
        mruby.handler: |
          proc {|env|
            sleep(1)
            [200, {}, ["hello"]]
          }
      /bar:
        mruby.handler: |
          proc {|env|
            [200, {}, ["hello"]]
          }
EOT
    my $pid = fork or do {
        run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/foo");
        exit;
    };
    Time::HiRes::sleep(0.5);
    my $st = Time::HiRes::time;
    (undef, my $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/bar");
    my $rtt = Time::HiRes::time - $st;
    is $body, 'hello';
    cmp_ok $rtt, '<=', 0.5;
    waitpid($pid, 0);
};

subtest 'argument error' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            ret = sleep(Object.new)
            [200, {}, [ret]]
          }
EOT
    my ($headers) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $headers, qr{HTTP/[^ ]+ 500\s}is;
};

done_testing;
