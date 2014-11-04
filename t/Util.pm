package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Proc::Wait3 qw(wait3);
use Scope::Guard qw(scope_guard);

use base qw(Exporter);
our @EXPORT = qw(spawn_h2o md5_file prog_exists openssl_can_negotiate);

# returns a hash containing `pid`, `port`, `tls_port`, `guard`
sub spawn_h2o {
    my ($conf) = @_;

    # decide the port numbers
    my $port = empty_port();
    my $tls_port = empty_port($port + 1);

    # fork
    my $pid = fork;
    die "fork failed:$!"
    unless defined $pid;
    if ($pid != 0) {
        # wait until the server becomes ready
        while (! (check_port($port) && check_port($tls_port))) {
            sleep 1;
            die "server died, abort"
                if defined wait3(0);
        }
        return +{
            pid      => $pid,
            port     => $port,
            tls_port => $tls_port,
            guard    => scope_guard(sub {
                kill 'TERM', $pid;
            }),
        };
    }

    # in child proces, setup the configuration file and exec the server
    my ($conffh, $conffn) = tempfile();
    print $conffh <<"EOT";
$conf
listen: $port
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
EOT
    exec "./h2o", "-c", $conffn;
    die "failed to spawn h2o:$!";
}

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

1;
