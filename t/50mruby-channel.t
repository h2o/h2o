use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "process integer" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            ch.push 1
            res = ch.shift
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, 1;
};

subtest "process string" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            ch.push "channel_value"
            res = ch.shift
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "channel_value";
};

subtest "process multiple channel" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch1 = H2O::Channel.new
            ch2 = H2O::Channel.new
            ch1.push "111"
            ch2.push "222"
            res2 = ch2.shift
            res1 = ch1.shift
            [200, {}, [res1 + res2]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "111222";

};

subtest "shift before push" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            res = nil
            task { res = ch.shift }
            ch.push "channel_value"
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "channel_value", "channel";

};

subtest "multipel shift for one channel" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            res1 = nil
            res2 = nil
            res3 = nil
            task { res1 = ch.shift }
            task { res2 = ch.shift }
            task { res3 = ch.shift }
            ch.push "c1"
            ch.push "c2"
            ch.push "c3"
            [200, {}, [res1, res2, res3]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "c1c2c3", "channel";

};

subtest "fiber-switch in constructor" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          class Klass
            def initialize(ch)
              task do
                ch.push [200, {}, ["hello world"]]
              end
            end
          end
          Proc.new do |env|
            ch = H2O::Channel.new
            Klass.new(ch)
            ch.shift
          end
EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "hello world";
};

done_testing();
