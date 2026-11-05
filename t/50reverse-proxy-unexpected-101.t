use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $upstream_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

for my $proto (qw(http1.1 http2)) {
    subtest $proto => sub {
        my $upstream = spawn_upstream();
        my $resp = `curl --silent --insecure --$proto --include https://127.0.0.1:$server->{tls_port}/ 2>&1`;
        like $resp, qr{^HTTP/[0-9.]+ 502 }s, "status";
        like $resp, qr{\r\n\r\nreceived unexpected 101 response$}s, "error message";
    };
}

undef $server;

done_testing;

sub spawn_upstream {
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
        $sock->syswrite("HTTP/1.1 101 Switching Protocols\r\n\r\nhello");
        while ($sock->sysread(my $buf, 4096)) {}
    });
    close $listen;
    return $upstream;
}
