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
      /assets:
        file.dir: @{[DOC_ROOT]}
EOT

sub doit {
    my ($proto, $opts, $port) = @_;

    my $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/index.txt?resp:link=</assets/index.js>\%3b\%20rel=preload'`;
    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.js\n.*\s/index\.txt\?}is, 'should receive pushed blocking asset from file handler before the main response';

    $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/index.txt?resp:link=</assets/index.txt>\%3b\%20rel=preload'`;
    like $resp, qr{\nid\s*responseEnd\s.*\s/index\.txt\?.*?\n.*\s/assets/index\.txt\n}is, 'should receive pushed non-blocking asset from file handler after the main response';

    $resp = `nghttp $opts -n --stat '$proto://127.0.0.1:$port/index.txt?resp:link=</index.txt.gz>\%3b\%20rel=preload'`;
    like $resp, qr{\nid\s*responseEnd\s.*\s/index\.txt\?.*\s/index\.txt.gz\n}is, 'pushed content on upstream would arrive after the main content';
}

subtest 'h2 direct' => sub {
    doit('http', '', $server->{port});
};
subtest 'h2 upgrade' => sub {
    doit('http', '-u', $server->{port});
};
subtest 'h2c' => sub {
    doit('https', '', $server->{tls_port});
};

done_testing;
