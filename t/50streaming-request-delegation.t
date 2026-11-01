use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

my $tempdir = tempdir(CLEANUP => 1);

my ($origin_port, $origin_guard) = one_shot_http_upstream("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nIt works!", empty_port());

# proxy.connect supports request streaming but passes requests other than CONNECT to the next handler, which does not
my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        proxy.connect:
          - "+127.0.0.1"
        mruby.handler: |
          proc {|env| [200, {}, [Digest::MD5.hexdigest(env["rack.input"].read)]] }
EOT

subtest "body sent in pieces over HTTP/1.1" => sub {
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server->{port}",
        Proto    => "tcp",
    ) or die "failed to connect to server:$!";
    $sock->syswrite("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello");
    sleep 0.5;
    $sock->syswrite("world");
    my $resp = do { local $/; <$sock> };
    like $resp, qr{^HTTP/1\.1 200 .*\r\n\r\n@{[md5_hex("helloworld")]}$}s;
};

subtest "large body" => sub {
    my $body = join "", map { chr(ord('a') + $_ % 26) } 0..(1024 * 1024 - 1);
    open my $fh, ">", "$tempdir/body" or die $!;
    print $fh $body;
    close $fh;
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --data-binary \@$tempdir/body $proto://127.0.0.1:$port/`;
        is $resp, md5_hex($body);
    });
};

subtest "CONNECT is handled" => sub {
    my $resp = `curl --http1.1 -p -x 127.0.0.1:$server->{port} --silent --show-error http://127.0.0.1:$origin_port/ 2>&1`;
    is $resp, "It works!";
};

done_testing;
