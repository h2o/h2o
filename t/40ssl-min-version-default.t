use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

# The security level is lowered on both sides, as OpenSSL 3 refuses TLS 1.0 and 1.1 at the default level regardless of the minimum
# version.
my $tls_port = empty_port();
my $server = spawn_h2o_raw(<< "EOT", [ $tls_port ]);
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    cipher-suite: "DEFAULT\@SECLEVEL=0"
EOT

sub handshake {
    my $version = shift;
    my $out = `openssl s_client -$version -cipher "DEFAULT\@SECLEVEL=0" -connect 127.0.0.1:$tls_port < /dev/null 2>&1`;
    return undef if $out =~ /^New, \(NONE\)/m;
    $out =~ /^Protocol: (\S+)/m ? $1 : undef;
}

subtest "TLS 1.2 is accepted" => sub {
    is handshake("tls1_2"), "TLSv1.2";
};

for my $version (qw(tls1 tls1_1)) {
    subtest "$version is rejected" => sub {
        plan skip_all => "openssl s_client does not support -$version"
            unless `openssl s_client -help 2>&1` =~ /^ -$version\s/m;
        is handshake($version), undef;
    };
}

done_testing;
