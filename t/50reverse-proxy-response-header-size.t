use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $upstream_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

subtest "within limit" => sub {
    my $resp = fetch(400000);
    like $resp, qr{^HTTP/1\.1 200 }m, "status";
    like $resp, qr{^ok$}m, "body";
};

subtest "exceeding limit" => sub {
    my $resp = fetch(420000);
    like $resp, qr{^HTTP/1\.1 502 .*\n\r?\nresponse headers too long$}ms, "502 reporting the error";
};

undef $server;

done_testing;

sub fetch {
    my $value_len = shift;
    my $listen = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto     => 'tcp',
        Listen    => 1,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$upstream_port:$!";
    my $upstream = spawn_forked(sub {
        my $sock = $listen->accept;
        # read the request before sending the response, then wait for h2o to close the connection, so that no RST is sent
        my $req = '';
        while ($req !~ /\r\n\r\n/) {
            $sock->sysread($req, 4096, length $req) or last;
        }
        $sock->print("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-large: @{['a' x $value_len]}\r\n\r\nok");
        while ($sock->sysread(my $buf, 4096)) {}
    });
    close $listen;
    return `$client_prog http://127.0.0.1:$server->{port}/ 2>&1`;
}
