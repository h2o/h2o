use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $upstream_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

subtest "error in the first read" => sub {
    my $body = fetch("3\r\nabc\r\nzz\r\n");
    is $body, "", "nothing from the broken read is forwarded";
};

subtest "error in a subsequent read" => sub {
    my $body = fetch("3\r\nabc\r\n", "zz\r\n");
    is $body, "abc", "chunks decoded from earlier reads are forwarded";
};

undef $server;

done_testing;

sub fetch {
    my @chunks = @_;
    my $listen = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto     => 'tcp',
        Listen    => 1,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$upstream_port:$!";
    my $upstream = spawn_forked(sub {
        my $sock = $listen->accept;
        my $req = '';
        while ($req !~ /\r\n\r\n/) {
            $sock->sysread($req, 4096, length $req) or last;
        }
        $sock->syswrite("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        for my $chunk (@chunks) {
            sleep 0.5;
            $sock->syswrite($chunk);
        }
        while ($sock->sysread(my $buf, 4096)) {}
    });
    close $listen;
    my ($stderr, $stdout) = run_prog("curl --silent --show-error http://127.0.0.1:$server->{port}/");
    like $stderr, qr/^curl: \(\d+\)/m, "curl reports an error";
    return $stdout;
}
