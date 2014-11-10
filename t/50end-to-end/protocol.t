use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

my %files = map { +($_ => md5_file("t/50end-to-end/protocol/docroot/$_")) } qw(index.txt halfdome.jpg);

my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: t/50end-to-end/protocol/docroot
EOT

my $port = $server->{port};
my $tls_port = $server->{tls_port};

subtest 'curl' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    for my $file (sort keys %files) {
        my $md5 = `curl --silent --show-error http://127.0.0.1:$port/$file | openssl md5 | perl -pe 's/.* //'`;
        is $md5, $files{$file}, "http://127.0.0.1/$file";
        $md5 = `curl --silent --show-error --insecure https://127.0.0.1:$tls_port/$file | openssl md5 | perl -pe 's/.* //'`;
        is $md5, $files{$file}, "https://127.0.0.1/$file";
    }
};

subtest 'nghttp' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $doit = sub {
        my ($proto, $port) = @_;
        my $opt = $proto eq 'http' ? '-u' : '';
        for my $file (sort keys %files) {
            my $md5 = `nghttp $opt $proto://127.0.0.1:$port/$file | openssl md5 | perl -pe 's/.* //'`;
            is $md5, $files{$file}, "$proto://127.0.0.1/$file";
        }
        my $out = `nghttp -u -m 100 $proto://127.0.0.1:$port/index.txt`;
        is $out, "hello\n" x 100, "$proto://127.0.0.1/index.txt x 100 times";
    };
    $doit->('http', $port);
    subtest 'https' => sub {
        plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
            unless openssl_can_negotiate();
        $doit->('https', $tls_port);
    };
};

subtest 'ab' => sub {
    plan skip_all => 'ab not found'
        unless prog_exists('ab');
    ok(system("ab -c 10 -n 10000 -k http://127.0.0.1:$port/index.txt") == 0);
    ok(system("ab -c 10 -n 10000 -k https://127.0.0.1:$tls_port/index.txt") == 0);
};

done_testing;
