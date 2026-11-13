use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();

my $tempdir = tempdir(CLEANUP => 1);

# the upstream ends the response while the request body is still blocked by its flow control window (it never sends
# WINDOW_UPDATE), then sends another HEADERS frame on the same stream
my $h2g = spawn_h2get_backend(<< "EOC");
    if f.type == 'HEADERS' then
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_HEADERS | END_STREAM)
        conn.send_headers({":status" => "200", "content-length" => "0"}, f.stream_id, END_HEADERS | END_STREAM)
    end
EOC

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}/
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
      /static:
        file.dir: @{[ DOC_ROOT ]}
EOT

wait_port($h2g->{tls_port});

{
    open my $fh, ">", "$tempdir/body" or die "failed to create file:$!";
    print $fh "x" x 1000000;
}

`curl --silent --show-error --max-time 3 --data-binary \@$tempdir/body http://127.0.0.1:$server->{port}/ 2>&1`;

my $resp = `curl --silent --show-error --max-time 3 http://127.0.0.1:$server->{port}/static/index.txt 2>&1`;
is $resp, "hello\n", "server is still alive";

$h2g->{kill}->();

done_testing();
