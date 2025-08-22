use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'openssl not found'
    unless prog_exists('openssl');

my $tempdir = tempdir(CLEANUP => 1);

diag `openssl version`;

# first port serves index.txt, alt port serves alice.txt
my ($local_port, $alt_port) = (empty_port(), empty_port());
my $server = spawn_h2o_raw(<< "EOT", [$local_port, $alt_port]);
hosts:
  localhost.examp1e.net:
    listen:
      host: 127.0.0.1
      port: $local_port
      ssl:
        key-file: examples/h2o/server.key
        certificate-file: examples/h2o/server.crt
    paths:
      /:
        file.file: t/assets/doc_root/index.txt
  alternate.localhost.examp1e.net:
    listen:
      host: 127.0.0.1
      port: $alt_port
      ssl:
        key-file: examples/h2o/alternate.key
        certificate-file: examples/h2o/alternate.crt
    paths:
      /:
        file.file: t/assets/doc_root/alice.txt
EOT

subtest "tls/1.2-session-id" => sub {
    subtest "without-sni" => sub {
        run_tests("-tls1_2 -no_ticket");
    };
    subtest "with-sni" => sub {
        run_tests("-tls1_2 -no_ticket -servername localhost.examp1e.net");
    };
};

subtest "tls/1.2-ticket" => sub {
    subtest "without-sni" => sub {
        run_tests("-tls1_2");
    };
    subtest "with-sni" => sub {
        run_tests("-tls1_2 -servername localhost.examp1e.net");
    };
};
subtest "tls/1.3-ticket" => sub {
    plan skip_all => "openssl s_client does not support tls/1.3"
        unless openssl_supports_tls13();
    subtest "without-sni" => sub {
        run_tests("-tls1_3");
    };
    subtest "with-sni" => sub {
        run_tests("-tls1_3 -servername localhost.examp1e.net");
    };
};

done_testing;

sub run_tests {
    my $opts = shift;
    unlink "$tempdir/session";
    subtest "full handshake" => sub {
        my $output = run_client("$opts -sess_out $tempdir/session -connect 127.0.0.1:$local_port", "localhost.examp1e.net");
        is get_common_name($output), "localhost.examp1e.net", "common name";
        like get_resp($output), qr/^hello/s, "response";
    };
    subtest "resume same port" => sub {
        my $output = run_client("$opts -sess_in $tempdir/session -connect 127.0.0.1:$local_port", "localhost.examp1e.net");
        is get_common_name($output), "localhost.examp1e.net", "common name";
        like get_resp($output), qr/^hello/s, "response";
    };
    subtest "resume alt port" => sub {
        my $output = run_client("$opts -sess_in $tempdir/session -connect 127.0.0.1:$alt_port", "localhost.examp1e.net");
        is get_common_name($output), "alternate.localhost.examp1e.net", "common name";
        like get_resp($output), qr/^Alice/s, "response";
    };
};

sub run_client {
    my ($ossl_opts, $authority) = @_;

    diag $ossl_opts;
    #sleep 100 if $ossl_opts =~ /tls1_3.*servername.*sess_in/;
    my $pid = open my $fh, "|-", "exec openssl s_client $ossl_opts > $tempdir/out 2>&1"
        or die "failed to spawn s_client:$?";
    $fh->autoflush(1);
    print $fh "GET / HTTP/1.0\r\nHost: $authority\r\n\r\n";

    while (waitpid($pid, 0) != $pid) {}

    close $fh;

    open $fh, "<", "$tempdir/out"
        or die "failed to open $tempdir/out:$!";
    my $output = do {
        local $/;
        <$fh>;
    };
    $output =~ /(.*read \d+ bytes.*)/m
        and diag $1;
    $output;
}

sub get_common_name {
    my $s = shift;
    $s =~ m{^subject=/?CN\s*=\s*(.*)}m
        or die "failed to extract common name from text:\n$s";
    $1;
}

sub get_resp {
    my $s = shift;
    $s =~ m{\nHTTP/1.1 200 OK\r\n(.*?)\r\n\r\n}s
        or die "failed to locate HTTP response in text:\n$s";
    $';
}
