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
  format: '"%r" %s %b %{extensible-priorities}x %{http3.stream-id}x %{response-time}x'
EOT

# returns the log lines that have become newly available since the last invocation
my $get_last_log = do {
    open my $fh, "<", "$tempdir/access_log"
        or die "failed to open file:$tempdir/access_log:$!";
    # for each invocation read whatever is available
    sub {
        my $input = '';
        sysread $fh, $input, 1048576;
        $input;
    };
};
$get_last_log->();

subtest "signalling" => sub {
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
            like $log, qr{^"GET / HTTP/3" 200 6 u=3 }, "logged priority";
        };
        subtest "u=7" => sub {
            my ($resp, $log) = $fetch->("u=7");
            like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
            like $log, qr{^"GET / HTTP/3" 200 6 u=7 }, "logged priority";
        };
        subtest "i=?1,u=0" => sub {
            my ($resp, $log) = $fetch->("i=?1,u=7");
            like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
            like $log, qr{^"GET / HTTP/3" 200 6 u=7,i=\?1 }, "logged priority";
        };
    };

    subtest "resp-header" => sub {
        subtest "u=0" => sub {
            my ($resp, $log) = $fetch->(undef, "u=1");
            like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
            like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=1 }s, "logged priority";
        };
        subtest "change-only-i" => sub {
            my ($resp, $log) = $fetch->("u=7", "i=?1");
            like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
            like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=7,i=\?1 }s, "logged priority";
        };
        subtest "change-only-u" => sub {
            my ($resp, $log) = $fetch->("u=6,i=?1", "u=1");
            like $resp, qr{^HTTP/3 200\n.*hello\n$}s, "response";
            like $log, qr{^"GET [^ ]+ HTTP/3" 200 6 u=1,i=\?1 }s, "logged priority";
        };
    };
};

# test delivery order; 120KB file is used to avoid the effect of the receive window of curl-ngtcp2 that happens to start at 128KB
subtest "delivery" => sub {
    plan skip_all => "curl not found"
        unless prog_exists("curl");
    plan skip_all => "curl does not support HTTP/3"
        unless curl_supports_http3();
    my $build_cmd = sub {
        "curl --parallel " . join(" --next", map {
            " --silent --insecure --http3 -H 'priority: @{[$_->[1]]}' https://127.0.0.1:@{[$server->{quic_port}]}@{[$_->[0]]}"
        } @_);
    };
    subtest "same-urgency" => sub {
        my $cmd = $build_cmd->(["/120k.bin?1", "u=3"], ["/120k.bin?2", "u=3"]);
        diag $cmd;
        system "$cmd > /dev/null";
        my $log = $get_last_log->();
        diag $log;
        like $log, qr{\?1 .* 200 .* u=3 .*\?2 .* 200 .* u=3 }s;
    };
    subtest "in-order" => sub {
        my $cmd = $build_cmd->(["/120k.bin?1", "u=1"], ["/120k.bin?2", "u=5"]);
        diag $cmd;
        system "$cmd > /dev/null";
        my $log = $get_last_log->();
        diag $log;
        like $log, qr{\?1 .* 200 .* u=1 .*\?2 .* 200 .* u=5 }s;
    };
    subtest "reverse-order" => sub {
        my $cmd = $build_cmd->(["/120k.bin?1", "u=5"], ["/120k.bin?2", "u=1"]);
        diag $cmd;
        system "$cmd > /dev/null";
        my $log = $get_last_log->();
        diag $log;
        like $log, qr{\?2 .* 200 .* u=1 .*\?1 .* 200 .* u=5 }s;
    };
    subtest "incremental" => sub {
        # first three files are u=2,i=?1 and the smallest one is delivered first; 4th file has lower urgency and is delivered last
        # even though it is tiny
        my $cmd = $build_cmd->(["/120k.bin?1", "u=2,i=?1"], ["/120k.bin?2", "u=2,i=?1"],  ["/alice.txt?3", "u=2,i=?1"], ["/alice.txt?4", "u=5,i=?1"]);
        diag $cmd;
        system "$cmd > /dev/null";
        my $log = $get_last_log->();
        diag $log;
        like $log, qr{\?3 .* 200 .* u=2,i=\?1 .*\?[12] .* 200 .* u=2,i=\?1 .*\?[12] .* 200 .* u=2,i=\?1 .*\?4 .* 200 .* u=5,i=\?1 }s;
    };
};

done_testing;
