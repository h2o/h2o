use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

my $dns_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $zone_rrs = [
    'bar.example.com. 60 IN AAAA 2001:db8::1',
    'foo.example.com. 60 IN AAAA 2001:db8::2',
    'foo.example.com. 60 IN AAAA 2001:db8::3',
    'bar.example.com. 60 IN A 127.0.0.2',
    'foo.example.com. 60 IN A 127.0.0.3'
    ];

my $delays = {'A' => 2, 'AAAA' => 1};

my $mock_dns = spawn_dns_server($dns_port, $zone_rrs, $delays);

subtest "dns_resp" => sub {
    my $resp;
    my $before = time();
    $resp = `dig +short \@127.0.0.1 -p $dns_port a foo.example.com`;
    my $after = time();
    like $resp, qr{^127.0.0.3};
    $resp = `dig +short \@127.0.0.1 -p $dns_port aaaa foo.example.com`;
    like $resp, qr{^2001:db8};
    ok(($after - $before) >= 2);
};

undef $mock_dns;

done_testing;
