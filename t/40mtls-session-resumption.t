use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => "could not find memcached"
    unless prog_exists("memcached");
plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

my $tempdir = tempdir(CLEANUP => 1);
my $client_cert_opts = "-cert t/assets/test_client.crt -key t/assets/test_client.key";

# start memcached
my $memc_port = empty_port();
my $memc_user = getlogin || getpwuid($<);
my $memc_guard = spawn_server(
    argv     => [ qw(memcached -l 127.0.0.1 -p), $memc_port, "-B", "binary", "-u", $memc_user ],
    is_ready => sub {
        check_port($memc_port);
    },
);

subtest "the integrity key is mandatory" => sub {
    throws_ok sub {
        spawn_h2o_raw(<< "EOT", [ empty_port() ]);
ssl-session-resumption:
  mode: cache
  cache-store: memcached
  memcached:
    host: 127.0.0.1
    port: $memc_port
    protocol: binary
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    }, qr/server failed to start/, 'external store without integrity-key';
};

# spawns an instance that stores the sessions on memcached and that verifies the certificates of the
# clients against the given CA; every instance is fresh, since it is the store that the instances share
sub spawn {
    my (%args) = @_;
    my $tls_port = empty_port();
    spawn_h2o_raw(<< "EOT", [$tls_port]);
ssl-session-resumption:
  mode: cache
  cache-store: memcached
  integrity-key: $args{integrity_key}
  memcached:
    host: 127.0.0.1
    port: $memc_port
    protocol: binary
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
listen:
  port: $tls_port
  ssl:
    max-version: tlsv1.2
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    client-ca-file: $args{client_ca}
EOT
    sleep 1; # wait for h2o to connect to memcached
    return $tls_port;
}

sub run_client {
    my ($port, $opts) = @_;
    run_openssl_client({ host => "127.0.0.1", port => $port, opts => "-no_ticket $opts" });
}

sub parse_handshake {
    my $lines = shift;
    $lines =~ m{---\n(New|Reused),}s
        or die "the handshake did not complete:{{{$lines}}}";
    return $1;
}

subtest "honest clients are not affected" => sub {
    my $port = spawn(integrity_key => "h2o-test-integrity-key", client_ca => "misc/test-ca/intermediate/ca.crt");
    my $lines = run_client($port, "$client_cert_opts -sess_out $tempdir/session");
    is parse_handshake($lines), "New";
    sleep 1; # wait for h2o to commit to the store
    $lines = run_client($port, "$client_cert_opts -sess_in $tempdir/session");
    is parse_handshake($lines), "Reused";
};

subtest "a value that does not carry the seal is not taken over" => sub {
    # the same session, offered to an instance that seals its values with another secret: the value
    # that the store holds fails the check, and the connection falls back to a full handshake
    my $port = spawn(integrity_key => "another-integrity-key", client_ca => "misc/test-ca/intermediate/ca.crt");
    my $lines = run_client($port, "$client_cert_opts -sess_in $tempdir/session");
    is parse_handshake($lines), "New";
};

subtest "the certificate that a resumed session carries is verified again" => sub {
    # the session was established against the intermediate CA; the instance that verifies the
    # clients against the root CA alone cannot vouch for the identity that the session carries
    my $port = spawn(integrity_key => "h2o-test-integrity-key", client_ca => "misc/test-ca/root/ca.crt");
    my $lines = run_client($port, "$client_cert_opts -sess_in $tempdir/session");
    like $lines, qr/ssl handshake failure/, "the handshake of a session that carries an identity the vhost does not vouch for fails";
};

done_testing;
