use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub { check_port($upstream_port) },
);
my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT


subtest 'POST' => sub {
    plan skip_all => 'curl not found' unless prog_exists('curl');

    for my $streaming (0, 1) {
        subtest $streaming ? 'streaming' : 'non-streaming', sub {
            my $size = $streaming ? 1024 * 1024 : 1024;
            my $file = create_data_file($size);
            my $file_md5 = md5_file($file);

            my ($stderr, $stdout) = run_prog(join(' ',
                'curl --silent --dump-header /dev/stderr --http2',
                "-X POST -d '\@$file' -H 'Expect: '",
                "http://127.0.0.1:$server->{port}/echo"));
            like $stderr, qr{HTTP/1.1 101 Switching Protocols}is;
            like $stderr, qr{HTTP/2 200}is;
            is md5_hex($stdout), $file_md5, 'body matches';
        };
    }
};

subtest 'OPTIONS' => sub {
    plan skip_all => 'nghttp not found' unless prog_exists('nghttp');

    my $file = create_data_file(1024 * 1024);
    my $file_md5 = md5_file($file);

    my $args = "-u -d $file http://127.0.0.1:$server->{port}/echo";
    my $resp = `nghttp -nv $args`;
    like $resp, qr{HTTP/1.1 101 Switching Protocols}is;
    like $resp, qr{recv \(stream_id=\d+\) :status: 200}is;
    unlike $resp, qr{recv \(stream_id=1\) :status:}is, 'OPTIONS request should not be processed';

    $resp = `nghttp $args`;
    is md5_hex($resp), $file_md5, 'body matches';
};

done_testing;

