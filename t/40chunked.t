use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'nc not found'
    unless prog_exists('nc');

sub fetch {
    my ($server, $path) = @_;
    my $resp = `echo 'GET $path HTTP/1.1\r\n\r\n' | nc 127.0.0.1 $server->{port}`;
    my ($headers, $body) = split(/^\r\n/m, $resp, 2);
    return ($headers, $body);
}

subtest 'push mode' => sub {
    plan skip_all => 'plackup not found'
        unless prog_exists('plackup');
    plan skip_all => 'Starlet not found'
        unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
    my $upstream_port = empty_port();
    my $upstream = spawn_server(
        argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
        is_ready =>  sub { check_port($upstream_port) },
    );
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my ($headers, $body) = fetch($server, '/streaming-body?sleep=0');
    like $headers, qr/^transfer-encoding: chunked\r$/m;
    my @list = split("\r\n", $body);
    my $content = '';
    while (scalar(@list) >= 2) {
        my ($len, $data) = splice(@list, 0, 2);
        is length($data), $len;
        $content .= $data;
    }
    is $content, join("", (1..30));
};

subtest 'pull mode' => sub {
    # server-timing forces chunked encoding in enforce mode
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
        server-timing: enforce
EOT
    my ($headers, $body) = fetch($server, '/');
    like $headers, qr/^transfer-encoding: chunked\r$/m;
    my $content = "hello\n";
    like $body, qr/^6\r\n$content\r\n0\r\nserver-timing: .+?\r\n\r\n$/;
    pass;
};

done_testing;

