package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);

use base qw(Exporter);
our @EXPORT = qw(ASSETS_DIR DOC_ROOT bindir exec_unittest spawn_server spawn_h2o create_data_file md5_file prog_exists openssl_can_negotiate);

use constant ASSETS_DIR => 't/assets';
use constant DOC_ROOT   => ASSETS_DIR . "/doc_root";

sub bindir {
    $ENV{BINARY_DIR} || '.';
}

sub exec_unittest {
    my $base = shift;
    my $fn = bindir() . "/t-00unit-$base.t";
    plan skip_all => "unit test:$base does not exist"
        if ! -e $fn;
    exec $fn;
    die "failed to exec $fn:$!";
}

# spawns a child process and returns a guard object that kills the process when destroyed
sub spawn_server {
    my %args = @_;
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid != 0) {
        print STDERR "spawning $args{argv}->[0]... ";
        if ($args{is_ready}) {
            while (1) {
                if ($args{is_ready}->()) {
                    print STDERR "done\n";
                    last;
                }
                if (waitpid($pid, WNOHANG) == $pid) {
                    die "server failed to start (got $?)\n";
                }
                sleep 0.1;
            }
        }
        my $guard = scope_guard(sub {
            print STDERR "killing $args{argv}->[0]... ";
            my $sig = 'TERM';
          Retry:
            if (kill $sig, $pid) {
                my $i = 0;
                while (1) {
                    if (waitpid($pid, WNOHANG) == $pid) {
                        print STDERR "killed (got $?)\n";
                        last;
                    }
                    if ($i++ == 100) {
                        if ($sig eq 'TERM') {
                            print STDERR "failed, sending SIGKILL... ";
                            $sig = 'KILL';
                            goto Retry;
                        }
                        print STDERR "failed, continuing anyways\n";
                        last;
                    }
                    sleep 0.1;
                }
            } else {
                print STDERR "no proc? ($!)\n";
            }
        });
        return wantarray ? ($guard, $pid) : $guard;
    }
    # child process
    exec @{$args{argv}};
    die "failed to exec $args{argv}->[0]:$!";
}

# returns a hash containing `port`, `tls_port`, `guard`
sub spawn_h2o {
    my ($conf) = @_;
    my @prefix = qw(catchsegv);

    # decide the port numbers
    my $port = empty_port();
    my $tls_port = empty_port($port + 1);

    # setup the configuration file
    my ($conffh, $conffn) = tempfile();
    $conf = $conf->($port, $tls_port)
        if ref $conf eq 'CODE';
    if (ref $conf eq 'HASH') {
        @prefix = @{$conf->{prefix}}
            if $conf->{prefix};
        $conf = $conf->{conf};
    }
    print $conffh <<"EOT";
$conf
listen:
  host: 0.0.0.0
  port: $port
listen:
  host: 0.0.0.0
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
EOT

    # spawn the server
    my ($guard, $pid) = spawn_server(
        argv     => [ @prefix, bindir() . "/h2o", "-c", $conffn ],
        is_ready => sub {
            check_port($port) && check_port($tls_port);
        },
    );
    return +{
        port     => $port,
        tls_port => $tls_port,
        guard    => $guard,
        pid      => $pid,
    };
}

sub create_data_file {
    my $sz = shift;
    my ($fh, $fn) = tempfile();
    print $fh '0' x $sz;
    close $fh;
    return $fn;
}

sub md5_file {
    my $fn = shift;
    open my $fh, "<", $fn
        or die "failed to open file:$fn:$!";
    local $/;
    return md5_hex(join '', <$fh>);
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
