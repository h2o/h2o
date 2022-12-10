use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $tls_port = empty_port();

my $ossl_version = server_features()->{OpenSSL};
plan skip_all => "x25519 may not be supported by $ossl_version"
    unless $ossl_version =~ /OpenSSL ([0-9]+\.[0-9]+)/ and $1 >= 1.1;

my $server = spawn_h2o_raw(<<"EOT", [ $tls_port ]);
num-threads: 1
listen:
  port: $tls_port
  ssl: &ssl
    identity:
    - key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
    ech:
    - key-file: examples/h2o/ech.key
      config-id: 0
      public-name: ech.examp1e.net
listen:
  port: $tls_port
  type: quic
  ssl:
    <<: *ssl
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

my $ech_config_fn = "$tempdir/echconfig";
my $trace_fn = "$tempdir/trace.out";


subtest "tcp" => sub {
    my $req_fn = "$tempdir/req";

    { # build request
        open my $fh, ">", $req_fn
            or die "failed to create file:$req_fn:$!";
        print $fh "GET /index.txt HTTP/1.0\r\n\r\n";
    }

    my $fetch = sub {
        open my $fh, "@{[bindir()]}/picotls/cli -j $trace_fn -I -E $ech_config_fn localhost.examp1e.net $tls_port < $req_fn |"
            or die "failed to launch @{[bindir()]}/picotls/cli:$!";
        join "", <$fh>;
    };

    create_empty_file($ech_config_fn);
    create_empty_file($trace_fn);

    # first connection is grease ECH
    my $resp = $fetch->();
    like $resp, qr{\r\n\r\nhello\n$}s, "response";
    sleep 0.1;
    ok !trace_says_ech(), "connection is non-ECH";
    isnt +(stat $ech_config_fn)[7], 0, "got retry_configs";

    create_empty_file($trace_fn);

    # second connection is ECH
    $resp = $fetch->();
    like $resp, qr{\r\n\r\nhello\n$}s, "response";
    sleep 0.1;
    ok trace_says_ech(), "connection is ECH";
};

subtest "quic" => sub {
    my $fetch = sub {
        open my $fh, "@{[bindir()]}/quicly/cli -a h3 -e $trace_fn --ech-configs $ech_config_fn localhost.examp1e.net $tls_port < /dev/null |"
            or die "failed to launch @{[bindir()]}/picotls/cli:$!";
        join "", <$fh>;
    };

    create_empty_file($ech_config_fn);
    create_empty_file($trace_fn);

    # first connection is grease ECH
    my $resp = $fetch->();
    sleep 0.1;
    ok !trace_says_ech(), "connection is non-ECH";
    isnt +(stat $ech_config_fn)[7], 0, "got retry_configs";

    create_empty_file($trace_fn);

    # second connection is ECH
    $resp = $fetch->();
    sleep 0.1;
    ok trace_says_ech(), "connection is ECH";
};

done_testing;

sub trace_says_ech {
    open my $fh, "<", $trace_fn
        or die "failed to open file:$trace_fn:$!";
    my $lines = join "", <$fh>;
    $lines =~ /[{,]"type":"ech_selection".*,"is_ech":(true|false)[,}]/
        or die "unexpected trace:$lines";
    $1 eq "true";
}

sub create_empty_file {
    my $fn = shift;
    open my $fh, ">", $fn
        or die "failed to create file:$fn:$!";
}
