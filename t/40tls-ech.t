use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $tls_port = empty_port();

my $ossl_version = server_features()->{OpenSSL};
plan skip_all => "x25519 may not be supported by $ossl_version"
    unless $ossl_version =~ /OpenSSL ([0-9]+\.[0-9]+)/ and $1 >= 1.1;

my $conf = <<"EOT";
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
        access-log:
          format: '\%s,\%{ssl.ech.config-id}x,\%{ssl.ech.kem}x,\%{ssl.ech.cipher}x,\%{ssl.ech.cipher-bits}x'
          path: $tempdir/access_log
EOT
if (server_features()->{mruby}) {
    $conf .= <<'EOT';
      /mruby:
        mruby.handler: |
          Proc.new do |env|
            [200, {"Content-Type" => "text/plain; charset=utf-8"}, [env["h2o.is_ech"].call()]]
          end
EOT
}

my $server = spawn_h2o_raw($conf, [ $tls_port ]);

my $ech_config_fn = "$tempdir/echconfig";
my $trace_fn = "$tempdir/trace.out";
my $stale_ech_config = pack "H*", join "", qw(
    0063fe0d005f13001000410439d2c8fb6fcc7972b2282033adc49701ffd691
    76aa1a11d93651b1b129d90ee0961f75fa19ffece2d791abf52939356690bf
    f35673cfc142c16e9925d2abdbb600080002000200010001400b6578616d70
    6c652e636f6d0000
);


subtest "tcp" => sub {
    my $req_fn = "$tempdir/req";

    my $fetch = sub {
        my ($path, $ech_config_fn) = @_;
        open my $fh, ">", "$tempdir/req"
            or die "failed to create file:$tempdir/req:$!";
        print $fh "GET $path HTTP/1.0\r\n\r\n";
        close $fh;
        my $ech_opt = defined($ech_config_fn) ? "-E $ech_config_fn" : "";
        open $fh, "@{[bindir()]}/picotls/cli -j $trace_fn -I $ech_opt localhost.examp1e.net $tls_port < $tempdir/req |"
            or die "failed to launch @{[bindir()]}/picotls/cli:$!";
        join "", <$fh>;
    };

    my $doit = sub {
        my ($path, $resp_non_ech, $resp_ech) = @_;
        create_empty_file($trace_fn);

        # first connection is non-ECH
        my $resp = $fetch->($path, undef);
        like $resp, $resp_non_ech, "non-ech response";

        write_stale_ech_config($ech_config_fn);
        create_empty_file($trace_fn);

        # second connection uses a stale ECH config and learns retry_configs
        $resp = $fetch->($path, $ech_config_fn);
        is $resp, "", "stale ech response";
        sleep 0.1;
        ok !trace_says_ech(), "connection is stale ECH";
        isnt +(stat $ech_config_fn)[7], 0, "got retry_configs";

        create_empty_file($trace_fn);

        # third connection is ECH
        $resp = $fetch->($path, $ech_config_fn);
        like $resp, $resp_ech, "ech response";
        sleep 0.1;
        ok trace_says_ech(), "connection is ECH";
    };

    subtest "index.txt" => sub {
        $doit->("/index.txt", qr{\r\n\r\nhello\n$}s, qr{\r\n\r\nhello\n$}s);
    };

    sleep 0.1;

    subtest "access-log" => sub {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open $tempdir/access_log:$!";
        my $get_success = sub {
            while (my $line = <$fh>) {
                chomp $line;
                my ($status, @rest) = split ",", $line;
                return @rest
                    if $status == 200;
            }
            die "unexpected end of access_log";
        };
        subtest "non-ech" => sub {
            my ($config_id, $kem, $cipher, $cipher_bits) = $get_success->();
            is $config_id, "-";
            is $kem, "-";
            is $cipher, "-";
            is $cipher_bits, "-";
        };
        subtest "ech" => sub {
            my ($config_id, $kem, $cipher, $cipher_bits) = $get_success->();
            is $config_id, "0";
            is $kem, "secp256r1";
            is $cipher, "HKDF-SHA256/AES-128-GCM";
            is $cipher_bits, "128";
        };
    };

    subtest "mruby" => sub {
        plan skip_all => "mruby handler not available"
            unless server_features()->{mruby};
        $doit->("/mruby", qr{\r\n\r\nfalse$}s, qr{\r\n\r\ntrue$}s);
    };
};

subtest "quic" => sub {
    my $fetch = sub {
        my $ech_opt = shift;
        $ech_opt = defined($ech_opt) ? "--ech-configs $ech_opt" : "";
        open my $fh, "@{[bindir()]}/quicly/cli -a h3 -e $trace_fn $ech_opt localhost.examp1e.net $tls_port < /dev/null |"
            or die "failed to launch @{[bindir()]}/picotls/cli:$!";
        join "", <$fh>;
    };

    write_stale_ech_config($ech_config_fn);
    create_empty_file($trace_fn);

    # first connection uses a stale ECH config and learns retry_configs
    my $resp = $fetch->($ech_config_fn);
    sleep 0.1;
    ok !trace_says_ech(), "connection is stale ECH";
    isnt +(stat $ech_config_fn)[7], 0, "got retry_configs";

    create_empty_file($trace_fn);

    # second connection is ECH
    $resp = $fetch->($ech_config_fn);
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

sub write_stale_ech_config {
    my $fn = shift;
    open my $out, ">", $fn
        or die "failed to create file:$fn:$!";
    binmode $out;
    print $out $stale_ech_config;
}
