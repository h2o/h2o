use strict;
use warnings;
use Net::EmptyPort qw(empty_port check_port);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};


my $upstream_hostport = "127.0.0.1:@{[empty_port()]}";

sub create_upstream {
    my @args = (
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen),
        $upstream_hostport,
        ASSETS_DIR . "/upstream.psgi",
    );
    spawn_server(
        argv     => \@args,
        is_ready =>  sub {
            $upstream_hostport =~ /:([0-9]+)$/s
                or die "failed to extract port number";
            check_port($1);
        },
    );
};

subtest "single task with multiple http requests" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            req_url = "http://$upstream_hostport/index.txt"
            req1 = http_request(req_url)
            req2 = http_request(req_url)
            req3 = http_request(req_url)
            task { req1.join; ch.push "1"; req2.join; ch.push "3"; req2.join; ch.push "5"; }
            res = ""
            res += ch.shift
            res += "2"
            res += ch.shift
            res += "4"
            res += ch.shift
            res += "6"
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "123456";
};

subtest "multiple tasks with multiple http requests" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch = H2O::Channel.new
            req_url = "http://$upstream_hostport/index.txt"
            req1 = http_request(req_url)
            req2 = http_request(req_url)
            req3 = http_request(req_url)
            task { req1.join; ch.push "1" }
            task { req2.join; ch.push "1"  }
            task { req3.join; ch.push "1"  }
            res = ""
            res += ch.shift
            res += "2"
            res += ch.shift
            res += "2"
            res += ch.shift
            res += "2"
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "121212";
};

subtest "multiple tasks with multiple channel" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            ch1 = H2O::Channel.new
            ch2 = H2O::Channel.new
            ch3 = H2O::Channel.new
            req_url = "http://$upstream_hostport/index.txt"
            req1 = http_request(req_url)
            req2 = http_request(req_url)
            req3 = http_request(req_url)
            task { req1.join; ch1.push "1" }
            task { req2.join; ch2.push "3"  }
            task { req3.join; ch3.push "5"  }
            res = ""
            res += ch1.shift
            res += "2"
            res += ch2.shift
            res += "4"
            res += ch3.shift
            res += "6"
            [200, {}, [res]]
          end

EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    is $stdout, "123456";
};

done_testing();
