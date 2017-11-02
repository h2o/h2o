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

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

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

done_testing();
