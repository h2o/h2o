use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "nc not found"
    unless prog_exists("nc");

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

my $resp;

$resp = `nc 127.0.0.1 $server->{port} < /dev/null 2>&1`;
is $resp, "", "silent close on empty request";

$resp = `echo "GET / HTTP/1.2\r\na\r\n\r" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*11.*\r\n\r\nBad Request$}is, "400 on broken request";

$resp = `echo "\r" | nc 127.0.0.1 $server->{port} 2>&1`;
is $resp, "", "silent close on CRLF";

$resp = `echo " / HTTP/1.1\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*11.*\r\n\r\nBad Request$}is, "missing method";

$resp = `echo "GET  HTTP/1.1\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*11.*\r\n\r\nBad Request$}is, "missing path";

$resp = `echo "GET / HTTP/1.1\r\nfoo: FOO\r\n    hoge\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*46.*\r\n\r\nline folding of header fields is not supported$}is, "multiline header";

$resp = `echo "GET / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*33.*\r\n\r\nrequest entity header already set$}is, "content-length and transfer-encoding present";

$resp = `echo "GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 400 .*Content-Length:\s*33.*\r\n\r\nrequest entity header already set$}is, "multiple content-length present";

$resp = `echo "GET / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" | nc 127.0.0.1 $server->{port} 2>&1`;
like $resp, qr{^HTTP/1\.1 200 OK\r\n}s, "multiple Transfer-Encoding";

done_testing;
