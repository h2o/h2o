use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $guard = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /least-conn/:
        proxy.reverse.url:
          backends:
            - url: http://localhost.examp1e.net:$upstream_port/
            - http://localhost.examp1e.net:$upstream_port/subdir/
          balancer: least-conn
      /:
        proxy.reverse.url:
          - http://localhost.examp1e.net:$upstream_port/
          - http://localhost.examp1e.net:$upstream_port/subdir/
EOT

my $expected1 = do {
    open my $fh, "<", "@{[DOC_ROOT]}/index.txt"
        or die "failed to open file:@{[DOC_ROOT]}/index.txt:$!";
    local $/;
    <$fh>;
};
my $expected2 = do {
    open my $fh, "<", "@{[DOC_ROOT]}/subdir/index.txt"
        or die "failed to open file:@{[DOC_ROOT]}/subdir/index.txt:$!";
    local $/;
    <$fh>;
};
my $body_re = qr/^@{[ join "|", map { quotemeta $_ } ($expected1, $expected2) ]}$/s;
my $access_count1 = 0;
my $access_count2 = 0;

for my $i (1..50) {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/index.txt`;
        like $resp, $body_re;
        if ($resp eq $expected1) {
            $access_count1 += 1;
        } else {
            $access_count2 += 1;
        }
    });
}

is $access_count1, $access_count2, "round robin applied";

$access_count1 = 0;
$access_count2 = 0;

for my $i (1..50) {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/least-conn/index.txt`;
        like $resp, $body_re;
        if ($resp eq $expected1) {
            $access_count1 += 1;
        } else {
            $access_count2 += 1;
        }
    });
}

# if upstream connections are always closed, least-conn will always connect to the same upstream when no other leased connection exists.
ok $access_count1 * $access_count2 == 0 && $access_count1 + $access_count2 > 0, "least conn applied";

done_testing();
