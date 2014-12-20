use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => +(stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt halfdome.jpg);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

my $port = $server->{port};
my $tls_port = $server->{tls_port};

subtest 'curl' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    for my $file (sort keys %files) {
        my $content = `curl --silent --show-error http://127.0.0.1:$port/$file`;
        is length($content), $files{$file}->{size}, "http://127.0.0.1/$file (size)";
        is md5_hex($content), $files{$file}->{md5}, "http://127.0.0.1/$file (md5)";
        $content = `curl --silent --show-error --insecure https://127.0.0.1:$tls_port/$file`;
        is length($content), $files{$file}->{size}, "http://127.0.0.1/$file (size)";
        is md5_hex($content), $files{$file}->{md5}, "https://127.0.0.1/$file (md5)";
    }
};

subtest 'nghttp' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $doit = sub {
        my ($proto, $port) = @_;
        my $opt = $proto eq 'http' ? '-u' : '';
        for my $file (sort keys %files) {
            my $content = `nghttp $opt $proto://127.0.0.1:$port/$file`;
            is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
            is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
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
