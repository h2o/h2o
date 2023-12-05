use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => "mruby support is off"
    unless server_features()->{mruby};

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          Proc.new do |env|
            q = env["QUERY_STRING"]
            h = {}
            if q
              h["priority"] = q
            end
            [399, h, []]
          end
        file.dir: @{[ DOC_ROOT ]}
access-log:
  path: $tempdir/access_log
  format: '"%r" %s %b %{extensible-priorities}x'
EOT

my $get_last_log = sub {
    open my $fh, "<", "$tempdir/access_log"
        or die "failed to open file:$tempdir/access_log:$!";
    sub {
        my $last = "";
        while (my $line = <$fh>) {
            $last = $line;
        }
        chomp $last;
        $last;
    };
}->();

my $fetch = sub {
    my ($reqval, $respval) = @_;
    my $opt = $reqval ? "-Hpriority:$reqval" : "";
    my $query = $respval ? "?$respval" : "";
    my $resp = `$client_prog -3 100 $opt https://127.0.0.1:$quic_port/$query 2>&1`;
    sleep 0.2;
    ($resp, $get_last_log->());
};

subtest "req-header" => sub {
    subtest "default" => sub {
        my ($resp, $log) = $fetch->();
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        is $log, '"GET / HTTP/3" 200 6 u=3', "logged priority";
    };
    subtest "u=7" => sub {
        my ($resp, $log) = $fetch->("u=7");
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        is $log, '"GET / HTTP/3" 200 6 u=7', "logged priority";
    };
    subtest "i=?1,u=0" => sub {
        my ($resp, $log) = $fetch->("i=?1,u=7");
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        is $log, '"GET / HTTP/3" 200 6 u=7,i=?1', "logged priority";
    };
};

subtest "resp-header" => sub {
    subtest "u=0" => sub {
        my ($resp, $log) = $fetch->(undef, "u=1");
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=1}s, "logged priority";
    };
    subtest "change-only-i" => sub {
        my ($resp, $log) = $fetch->("u=7", "i=?1");
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=7,i=\?1}s, "logged priority";
    };
    subtest "change-only-u" => sub {
        my ($resp, $log) = $fetch->("u=6,i=?1", "u=1");
        like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
        like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=1,i=\?1}s, "logged priority";
    };
};

done_testing;
