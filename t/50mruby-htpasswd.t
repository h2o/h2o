use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "basic" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          require "share/h2o/mruby/htpasswd.rb"
          Htpasswd.new("t/assets/.htpasswd", "protected space")
        mruby.handler:
          Proc.new do |env|
            [200, {}, ["hello ", env["REMOTE_USER"], "\n"]]
          end
EOT
    subtest "no-auth" => sub {
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
        like $headers, qr{^HTTP/1\.1 401 }s, "status";
        like $headers, qr{\r\nwww-authenticate: basic realm="protected space"\r}is, "www-authenticate header";
        unlike $body, qr/hello/;
    };

    subtest "fail" => sub {
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://aaa:aaa\@127.0.0.1:$server->{port}/");
        like $headers, qr{^HTTP/1\.1 401 }s, "status";
        like $headers, qr{\r\nwww-authenticate: basic realm="protected space"\r}is, "www-authenticate header";
        unlike $body, qr/hello/;
    };

    subtest "success" => sub {
        my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://dankogai:kogaidan\@127.0.0.1:$server->{port}/");
        like $headers, qr{^HTTP/1\.1 200 }s, "status";
        is $body, "hello dankogai\n", "content";
    };
};

done_testing();
