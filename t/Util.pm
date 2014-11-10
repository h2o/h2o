package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);

use base qw(Exporter);
our @EXPORT = qw(spawn_server spawn_h2o md5_file prog_exists openssl_can_negotiate);

# spawns a child process and returns a guard object that kills the process when destroyed
sub spawn_server {
    my %args = @_;
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid != 0) {
        if ($args{is_ready}) {
            while (! $args{is_ready}->()) {
                sleep 1;
                die "server died"
                    if waitpid($pid, WNOHANG) == $pid;
            }
        }
        return scope_guard(sub {
            if (kill 'TERM', $pid) {
                while (waitpid($pid, 0) != $pid) {
                }
            }
        });
    }
    # child process
    exec @{$args{argv}};
    die "failed to exec $args{argv}->[0]:$!";
}

# returns a hash containing `port`, `tls_port`, `guard`
sub spawn_h2o {
    my ($conf) = @_;

    # decide the port numbers
    my $port = empty_port();
    my $tls_port = empty_port($port + 1);

    # setup the configuration file
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

    # spawn the server
    my $guard = spawn_server(
        argv     => [ qw(./h2o -c), $conffn ],
        is_ready => sub {
            check_port($port) && check_port($tls_port);
        },
    );
    return +{
        port     => $port,
        tls_port => $tls_port,
        guard    => $guard,
    };
}

sub md5_file {
    my $fn = shift;
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
