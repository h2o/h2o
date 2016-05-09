use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');
plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "basic" => sub {
    # spawn upstream
    my $upstream_port = empty_port();
    my $upstream = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null -p), $upstream_port, ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($upstream_port);
        },
    );
    # spawn server
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /mruby:
        mruby.handler: |
          Proc.new do |env|
            [399, { "link" => "</index.txt.gz>; rel=preload" }, [] ]
          end
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /assets:
        file.dir: @{[DOC_ROOT]}
EOT

    my $doit = sub {
        my ($proto, $opts, $port) = @_;
        subtest 'push-prioritized' => sub {
            my $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/index.txt?resp:link=</assets/index.js>\%3b\%20rel=preload'`;
            like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.js\n.*\s/index\.txt\?}is;
        };
        subtest 'push-unprioritized' => sub {
            my $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/index.txt?resp:link=</index.txt.gz>\%3b\%20rel=preload'`;
            like $resp, qr{\nid\s*responseEnd\s.*\s/index\.txt\?.*\s/index\.txt.gz\n}is;
        };
        subtest 'push-while-sleep' => sub {
            my $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/mruby/sleep-and-respond?sleep=1'`;
            like $resp, qr{\nid\s*responseEnd\s.*\s/index\.txt\.gz\n.*\s/mruby/sleep-and-respond}is;
        };
    };

    subtest 'h2 direct' => sub {
        $doit->('http', '', $server->{port});
    };
    subtest 'h2 upgrade' => sub {
        $doit->('http', '-u', $server->{port});
    };
    subtest 'h2c' => sub {
        $doit->('https', '', $server->{tls_port});
    };
};

subtest "push-after-reproxy" => sub {
    subtest "authority-match" => sub {
        my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            return << "EOT";
hosts:
  "127.0.0.1:$tls_port":
    paths:
      /:
        reproxy: ON
        mruby.handler: |
          Proc.new do |env|
            case env["PATH_INFO"]
            when "/reproxy"
              [307, {"x-reproxy-url" => "/index.txt"}, ["should never see this"]]
            when "/index.txt"
              push_paths = []
              push_paths << "/index.js"
              [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join("\\n")}, []]
            else
              [399, {}, []]
            end
          end
        file.dir: t/assets/doc_root
EOT
        });
        my $resp = `nghttp -n --stat https://127.0.0.1:$server->{tls_port}/reproxy`;
        like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n.*\s/reproxy}is, "receives index.js then /reproxy";
    };
    subtest "authority-mismatch" => sub {
        my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            return << "EOT";
hosts:
  default:
    paths:
      /:
        reproxy: ON
        mruby.handler: |
          Proc.new do |env|
            case env["PATH_INFO"]
            when "/reproxy"
              [307, {"x-reproxy-url" => "/index.txt"}, ["should never see this"]]
            when "/index.txt"
              push_paths = []
              push_paths << "/index.js?1"
              push_paths << "https://127.0.0.1:$tls_port/index.js?2"
              [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join("\\n")}, []]
            else
              [399, {}, []]
            end
          end
        file.dir: t/assets/doc_root
EOT
        });
        my $resp = `nghttp -n --stat https://127.0.0.1:$server->{tls_port}/reproxy`;
        like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\?2\n.*\s/reproxy}is, "receives index.js?2 then /reproxy";
        unlike $resp, qr{/index\.js\?1\n}is, "index.js?1 not received (authority mismatch)";
    };
};

subtest "casper" => sub {
    subtest "custom capacity-bits" => sub {
        my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            return << "EOT";
hosts:
  "127.0.0.1:$tls_port":
    http2-casper:
      capacity-bits:  11
    paths:
      /:
        reproxy: ON
        mruby.handler: |
          Proc.new do |env|
            case env["PATH_INFO"]
            when "/index.txt"
              push_paths = []
              push_paths << "/index.js"
              [399, push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join("\\n")}, []]
            else
              [399, {}, []]
            end
          end
        file.dir: t/assets/doc_root
EOT
        });
        my $resp = `nghttp -v -n --stat https://127.0.0.1:$server->{tls_port}/index.txt`;
        like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n.*\s/index.txt}is, "receives index.js then /index.txt";
        my ($casper) = ($resp =~ qr{set-cookie:\s*(h2o_casper=[^\s;]+)}i);

        is length($casper), 17;

        {
            my $resp = `nghttp -H'cookie: $casper' -v -n --stat https://127.0.0.1:$server->{tls_port}/index.txt`;
            unlike $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n}is, "does not receives index.js";
        }
    };
};

done_testing;
