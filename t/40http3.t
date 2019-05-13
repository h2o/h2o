use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

sub doit {
    my $num_threads = shift;
    my $guard = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  quic:
    event-log: /dev/stderr
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
num-threads: $num_threads
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
    subtest "hello world" => sub {
        my $resp = `$client_prog -3 https://127.0.0.1:$quic_port 2>&1`;
        like $resp, qr{^HTTP/.*\n\nhello\n$}s;
    };
    subtest "large file" => sub {
        my $resp = `$client_prog -3 https://127.0.0.1:$quic_port/halfdome.jpg 2> $tempdir/log`;
        is $?, 0;
        diag do {
            open my $fh, '<', "$tempdir/log"
                or die "failed to open $tempdir/log:$!";
            local $/;
            <$fh>;
        } if $? != 0;
        is length($resp), (stat "t/assets/doc_root/halfdome.jpg")[7];
        is md5_hex($resp), md5_file("t/assets/doc_root/halfdome.jpg");
    };
};

subtest "single-thread" => sub {
    doit(1);
};

subtest "multi-thread" => sub {
    doit(16);
};

done_testing;
