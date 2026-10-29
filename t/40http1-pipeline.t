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
    my $resp = send_and_receive($server->{port}, <<"EOT");
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
    my $resp = send_and_receive($server->{port}, <<"EOT");
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
    my $resp = send_and_receive($server->{port}, <<"EOT");
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

subtest "content-length and transfer-encoding" => sub {
    for my $reverse (0, 1) {
        for my $keep_alive (0, 1) {
            subtest "reverse=$reverse, keep-alive=$keep_alive" => sub {
                my @headers = ("Content-Length: 1000000\r\n", "Transfer-Encoding: chunked\r\n");
                @headers = reverse @headers if $reverse;
                push @headers, "Connection: keep-alive\r\n" if $keep_alive;
                my $resp = send_and_receive($server->{port},
                    "POST / HTTP/1.1\r\nHost: 127.0.0.1:$server->{port}\r\n" . join('', @headers) .
                    "\r\n5\r\nabc\r\n\r\n0\r\n\r\n" .
                    "GET / HTTP/1.1\r\nHost: 127.0.0.1:$server->{port}\r\nConnection: close\r\n\r\n");
                like $resp, qr{^HTTP/1\.1 405 Method Not Allowed\r\n}, "chunked request is processed";
                my ($resp_headers) = split /\r\n\r\n/, $resp, 2;
                like $resp_headers, qr{^connection: close\r?$}mi, "connection is closed";
                is scalar(() = $resp =~ /HTTP\/1\.1 /g), 1, "pipelined request is not processed";
            };
        }
    }
};

done_testing;

sub send_and_receive {
    my($port, $req) = @_;
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$port",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    syswrite($sock, $req) == length($req) or die "syswrite failed:$!";
    my $resp = '';
    while (sysread($sock, $resp, 65536, length($resp)) != 0) {}
    $resp;
}

