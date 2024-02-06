use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use Time::HiRes;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });
my $server = spawn_h2o({conf => <<"EOT", max_ssl_version => 'TLSv1.3'});
send-informational: all
num-threads: 1
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /non-streaming:
        mruby.handler: |
          proc do |env|
            # \$stderr.puts env.inspect
            [200, {}, env['rack.input']]
          end
      /streaming:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/echo
EOT
$server->{quic_port} = $quic_port;

for my $proto ('h1', 'h2', 'h3') {
subtest $proto => sub {
    plan skip_all => "curl does not support HTTP/2"
        if $proto eq 'h2' && !curl_supports_http2();
    plan skip_all => "curl does not support HTTP/3"
        if $proto eq 'h3' && !curl_supports_http3();

    my $opts = +{
        h1 => '--http1.1',
        h2 => '--http2',
        h3 => '--http3',
    }->{$proto};

    for my $mode ('streaming', 'non-streaming') {
    subtest $mode => sub {
        my $resp = `curl $opts -ks --dump-header /dev/stderr -X POST --data-binary -xxxxx -H "expect: 100-continue" 'https://127.0.0.1:@{[ $proto eq 'h3' ? $server->{quic_port} : $server->{tls_port} ]}/$mode' 2>&1`;
        like $resp, qr{HTTP/[0-9.]+ 100\s.*HTTP/[0-9.]+ 200\s}is;
    };
    }
};
}

done_testing;
