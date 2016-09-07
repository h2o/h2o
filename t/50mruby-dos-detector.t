use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "default callback" => sub {
    my $server = spawn_h2o(<< 'EOT');
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          require "share/h2o/mruby/dos_detector.rb"
          DoSDetector.new({
            :strategy => DoSDetector::CountingStrategy.new({ :period => 1000, :threshold => 2, :ban_period => 1 << 32 }),
          })
        mruby.handler:
          Proc.new do |env|
            [200, {}, []]
          end
EOT
    subtest "forbidden" => sub {
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 200 }s, "status";
        }
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 403 }s, "status";
            is $body, "Forbidden", "content";
        }
    };
};

subtest "fallthrough callback" => sub {
    my $server = spawn_h2o(<< 'EOT');
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          require "share/h2o/mruby/dos_detector.rb"
          DoSDetector.new({
            :strategy => DoSDetector::CountingStrategy.new({ :period => 1000, :threshold => 2, :ban_period => 1 << 32 }),
            :callback => DoSDetector.fallthrough_callback,
          })
        mruby.handler:
          Proc.new do |env|
            [200, {}, ["DOS_COUNT is ", env["DOS_COUNT"], ", DOS_IP is ", env["DOS_IP"]]]
          end
EOT
    subtest "success" => sub {
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 200 }s, "status";
        }
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 200 }s, "status";
            is $body, "DOS_COUNT is 2, DOS_IP is 127.0.0.1", "content";
        }
    };
};

subtest "customized callback" => sub {
    my $server = spawn_h2o(<< 'EOT');
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          require "share/h2o/mruby/dos_detector.rb"
          DoSDetector.new({
            :strategy => DoSDetector::CountingStrategy.new({ :period => 1000, :threshold => 2, :ban_period => 1 << 32 }),
            :callback => Proc.new do |env, detected, ip|
              if detected
                [503, {}, ["Service Unavailable"]]
              else
                [399, {}, []]
              end
            end
          })
        mruby.handler:
          Proc.new do |env|
            [200, {}, []]
          end
EOT
    subtest "success" => sub {
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 200 }s, "status";
        }
        {
            my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
            like $headers, qr{^HTTP/1\.1 503 }s, "status";
            is $body, "Service Unavailable", "content";
        }
    };
};

done_testing();
