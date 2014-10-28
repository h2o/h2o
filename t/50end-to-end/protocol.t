use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Proc::Wait3 qw(wait3);
use Scope::Guard qw(scope_guard);
use Test::More;

my %files = map { +($_ => md5_file($_)) } qw(index.txt halfdome.jpg);

my $port = empty_port();
my $tls_port = empty_port($port + 1);

# spawn the server
my $pid = fork;
die "fork failed:$!"
    unless defined $pid;
if ($pid == 0) {
    # write configuration and start h2o
    my ($conffh, $conffn) = tempfile();
    print $conffh <<"EOT";
listen: $port
listen:
  port: $tls_port
  ssl:
    key-file: t/50end-to-end/protocol/server.key
    certificate-file: t/50end-to-end/protocol/server.crt
hosts:
  "localhost:$port":
    paths:
      /:
        file.dir: t/50end-to-end/protocol/docroot
    mime-types:
      txt: text/plain
      jpg: image/jpeg
EOT
    exec "./h2o", "-c", $conffn;
    die "failed to spawn h2o:$!";
}
my $guard = scope_guard(sub {
    kill 'TERM', $pid;
});

while (! (check_port($port) && check_port($tls_port))) {
    sleep 1;
    die "server died, abort"
        if defined wait3(0);
}

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

sub md5_file {
    my $fn = shift;
    $fn = "t/50end-to-end/protocol/docroot/$fn";
    open my $fh, "<", $fn
        or die "failed to open file:$fn:$!";
    local $/;
    return md5_hex(join '', <$fh>) . "\n";
}

sub prog_exists {
    my $prog = shift;
    system("which $prog > /dev/null 2>&1") == 0;
}

sub openssl_can_negotiate {
    my $openssl_ver = `openssl version`;
    $openssl_ver =~ /^\S+\s(\d+)\.(\d+)\.(\d+)/
        or die "cannot parse OpenSSL version: $openssl_ver";
    $openssl_ver = $1 * 10000 + $2 * 100 + $3;
    return $openssl_ver >= 10001;
}
