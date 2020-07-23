use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port wait_port);
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
    my $conf = << "EOT";
listen:
  type: quic
  port: $quic_port
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
    if (server_features()->{mruby}) {
        $conf .= << 'EOT';
      /echo:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [env["rack.input"].read]]
          end
EOT
    }
    my $guard = spawn_h2o($conf);
    wait_port({port => $quic_port, proto => 'udp'});
    for (1..100) {
        subtest "hello world" => sub {
            my $resp = `$client_prog -3 https://127.0.0.1:$quic_port 2>&1`;
            like $resp, qr{^HTTP/.*\n\nhello\n$}s;
        };
        subtest "large file" => sub {
            my $resp = `$client_prog -3 https://127.0.0.1:$quic_port/halfdome.jpg 2> $tempdir/log`;
            is $?, 0;
            diag do {
                open my $fh, "-|", "share/h2o/annotate-backtrace-symbols < $tempdir/log"
                    or die "failed to open $tempdir/log through annotated-backtrace-symbols:$?";
                local $/;
                <$fh>;
            } if $? != 0;
            is length($resp), (stat "t/assets/doc_root/halfdome.jpg")[7];
            is md5_hex($resp), md5_file("t/assets/doc_root/halfdome.jpg");
        };
        subtest "more than stream-concurrency" => sub {
            my $resp = `$client_prog -3 -t 1000 https://127.0.0.1:$quic_port 2> /dev/null`;
            is $resp, "hello\n" x 1000;
        };
        subtest "post" => sub {
            plan skip_all => 'mruby support is off'
                unless server_features()->{mruby};
            foreach my $cl (1, 100, 10000, 1000000) {
                my $resp = `$client_prog -3 -b $cl -c 100000 https://127.0.0.1:$quic_port/echo 2> /dev/null`;
                is length($resp), $cl;
                ok +($resp =~ /^a+$/s); # don't use of `like` to avoid excess amount of log lines on mismatch
            }
        };
    }
};

subtest "single-thread" => sub {
    doit(1);
};

subtest "multi-thread" => sub {
    doit(16);
};

subtest "slow-echo-chunked" => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};

    my $guard = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /echo:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, env["rack.input"]]
          end
EOT

    wait_port({port => $quic_port, proto => 'udp'});

    my $resp = `$client_prog -3 -t 5 -d 1000 -b 10 -c 2 -i 1000 https://127.0.0.1:$quic_port/echo 2> /dev/null`;
    is length($resp), 50;
    is $resp, 'a' x 50;
};

done_testing;
