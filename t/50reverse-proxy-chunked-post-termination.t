use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

# This test detects an existing bug that http1client unintentionally sends '0\r\n'
# as a chunked encoding terminator instead of the correct one ('0\r\n\r\n').
# As a result of the bug, some server implementations (including h2o)
# indefinitely waits a terminator or responds an error indicating timeout.

my $upstream = spawn_h2o(<< "EOT");
http1-request-timeout: 1
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          proc {|env|
            [200, {}, [env['rack.input'].read]]
          }
EOT

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream->{port}
EOT

my $sock = IO::Socket::INET->new(
    PeerHost => q(127.0.0.1),
    PeerPort => $server->{port},
    Proto    => 'tcp'
) or die "failed to connect to 127.0.0.1$server->{port}:$!";

syswrite $sock, "POST / HTTP/1.1\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n1\r\nX\r\n";
sleep 0.1; # force streaming, otherwise http1cliennt sends content-length header
syswrite $sock, "0\r\n\r\n";

my $resp = '';
while (sysread($sock, my $buf, 1000)) { $resp .= $buf; }

# If the bug exists, upstream fires http1 request timeout after 1 second
# that causes immediate closing of the connection. Then the server gets
# `socket closed by peer` error and then responds 502 with the message `I/O error (head)`.

like $resp, qr{HTTP/1.1 200\s}m;

done_testing();

