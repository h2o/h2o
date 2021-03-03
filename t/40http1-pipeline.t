use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

subtest "2 gets" => sub {
    my $resp = send_and_receive(<<"EOT");
GET / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
\r
GET / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
Connection: close\r
\r
EOT
    like $resp, qr{^HTTP/1.1 200 OK\r\n.*HTTP/1.1 200 OK\r\n.*}s;
};

subtest "post(content-lenth) and get" => sub {
    my $resp = send_and_receive(<<"EOT");
POST / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
Content-Length: 5\r
\r
abc\r
GET / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
Connection: close\r
\r
EOT
    like $resp, qr{^HTTP/1.1 405 Method Not Allowed\r\n.*HTTP/1.1 200 OK\r\n.*}s;
};

subtest "post(chunked) and get" => sub {
    my $resp = send_and_receive(<<"EOT");
POST / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
Transfer-Encoding: chunked\r
\r
5\r
abc\r
\r
0\r
\r
GET / HTTP/1.1\r
Host: 127.0.0.1:$server->{port}\r
Connection: close\r
\r
EOT
    like $resp, qr{^HTTP/1.1 405 Method Not Allowed\r\n.*HTTP/1.1 200 OK\r\n.*}s;
};

done_testing;

sub send_and_receive {
    my $req = shift;
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server->{port}",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    syswrite($sock, $req) == length($req) or die "syswrite failed:$!";
    my $resp = '';
    while (sysread($sock, $resp, 65536, length($resp)) != 0) {}
    $resp;
}

