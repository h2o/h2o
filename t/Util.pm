package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Errno qw(EEXIST);
use File::Path qw(rmtree);
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Path::Tiny;
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);
use Fcntl qw(:flock O_RDWR O_CREAT O_EXCL);

use base qw(Exporter);
our @EXPORT = qw(ASSETS_DIR DOC_ROOT bindir server_features exec_unittest exec_mruby_unittest spawn_server spawn_h2o empty_ports create_data_file md5_file prog_exists run_prog openssl_can_negotiate curl_supports_http2 run_with_curl safe_empty_port safe_empty_port_release);

use constant ASSETS_DIR => 't/assets';
use constant DOC_ROOT   => ASSETS_DIR . "/doc_root";

sub safe_empty_port_release {
    my $epdir = $ENV{'SAFE_EMPTY_PORT_DIR'};
    return unless $epdir;
    my $port = shift;
    safe_empty_port_lock();
    unlink("${epdir}/${port}");
    safe_empty_port_unlock();
}

sub safe_empty_port {
    my $port;
    safe_empty_port_lock();
    my $tries = 0;
    do {
        if ($tries++ > 0xffff) {
            die "Failed to allocate an empty port";
        }
        $port = empty_port();
    } while (!safe_empty_port_acquire($port));
    safe_empty_port_unlock();
    return $port;
}

sub empty_ports {
    my $n = shift;
    my @ports;
    while (@ports < $n) {
        my $t = safe_empty_port();
        push @ports, $t;
    }
    return @ports;
}

sub safe_empty_port_acquire {
    my $epdir = $ENV{'SAFE_EMPTY_PORT_DIR'};
    return 1 unless $epdir;

    my $port = shift;
    my $file_name = "${epdir}/${port}";

    if (-e "${file_name}") {
        return 0;
    }

    open(my $fh, '>', ${file_name}) or die "Failed to create aquisition file '${file_name}': $!";
    close($fh);

    return 1;
}

sub safe_empty_port_lock {
    my $epdir = $ENV{'SAFE_EMPTY_PORT_DIR'};
    return unless $epdir;
    my $path = "${epdir}/.lock";
    my $ret = 0;
    while (1) {
        unless(sysopen(my $fh, $path, O_RDWR|O_CREAT|O_EXCL)) {
            if ($!{EEXIST}) {
                sleep 0.01;
                next;
            }
            die "Error opening '$path': $!";
        };
        last;
    }
}

sub safe_empty_port_check {
    my $epdir = $ENV{'SAFE_EMPTY_PORT_DIR'};
    return 0 unless $epdir;
    my $count;
    opendir(my $dh, $epdir) or die "Can't open directory '$epdir': $!";
    while (my $de = readdir($dh)) {
        next if $de == "." or $de == "..";
        $count++;
    }
    closedir($dh);
    return $count;
}

sub safe_empty_port_unlock {
    my $epdir = $ENV{'SAFE_EMPTY_PORT_DIR'};
    return unless $epdir;
    unlink("${epdir}/.lock");
}

sub bindir {
    $ENV{BINARY_DIR} || '.';
}

sub server_features {
    open my $fh, "-|", bindir() . "/h2o", "--version"
        or die "failed to invoke: h2o --version:$!";
    <$fh>; # skip h2o version
    +{
        map { chomp($_); split /:/, $_, 2 } <$fh>
    };
}

sub exec_unittest {
    my $base = shift;
    my $fn = bindir() . "/t-00unit-$base.t";
    plan skip_all => "unit test:$base does not exist"
        if ! -e $fn;

    if (prog_exists("memcached")) {
        my $port = empty_port();
        pipe my $rfh, my $wfh
            or die "pipe failed:$!";
        my $pid = fork;
        die "fork failed:$!"
            unless defined $pid;
        if ($pid == 0) {
            # child process
            close $wfh;
            POSIX::dup2($rfh->fileno, 5)
                or die "dup2 failed:$!";
            exec qw(share/h2o/kill-on-close -- memcached -l 127.0.0.1 -p), $port;
            exit 1;
        }
        close $rfh;
        POSIX::dup($wfh->fileno)
            or die "dup failed:$!";
        sleep 1;
        if (waitpid($pid, WNOHANG) == $pid) {
            die "failed to launch memcached";
        }
        $ENV{MEMCACHED_PORT} = $port;
    }

    exec $fn;
    die "failed to exec $fn:$!";
}

sub exec_mruby_unittest {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};

    my $test_dir = path('t/00unit.mruby');
    my $bin = path(bindir(), 'mruby/host/bin/mruby');
    unless (-e $bin) {
        die "unit test: mruby binary $bin does not exist";
    }

	my $k = 0;
    $test_dir->visit(sub {
        my ($path) = @_;
        return unless $path =~ /\.rb$/;

        my $fn = "$bin $path";
        my $output = `$fn`;

		# parse mruby test output
		$output =~ /# Running tests:\n\n([SFE\.]+)\n/
			or die "cannot parse test output for $path";
		my ($i, $j) = (0, 0);
		my @results = map { +{ type => $_, index => ++$i, failed => ($_ eq 'F' || $_ eq 'E') } } split(//, $1);
		while ($output =~ /\d\) (Skipped|Failure|Error):\n([^\n]+)/g) {
			my ($type, $detail) = (substr($1, 0, 1), $2);
			while ($results[$j]->{type} ne $type) { $j++; }
			$results[$j++]->{detail} = $detail;
		}

		# print TAP compatible output
		printf("%s %s\n", $path, '.' x (51 - length($path)));
		for my $r (@results) {
			printf("    %s %d - %s\n", $r->{failed} ? 'not ok' : 'ok', $r->{index}, $r->{detail} || '');
			printf STDERR ("# Error - %s\n", $r->{detail}) if $r->{failed};
		}
		printf("    1..%d\n", scalar(@results));
		printf("%s %d - %s\n", (grep { $_->{failed} } @results) ? 'not ok' : 'ok', ++$k, $path);

    }, +{ recurse => 1 });

	printf("1..%d\n", $k);
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
    my @opts;

    # decide the port numbers
    my ($port, $tls_port) = empty_ports(2);

    # setup the configuration file
    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    $conf = $conf->($port, $tls_port)
        if ref $conf eq 'CODE';
    if (ref $conf eq 'HASH') {
        @opts = @{$conf->{opts}}
            if $conf->{opts};
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
    my ($guard, $pid) = eval {
        spawn_server(
            argv     => [ bindir() . "/h2o", "-c", $conffn, @opts ],
            is_ready => sub {
                check_port($port) && check_port($tls_port);
            },
        );
    };
    if ($@) {
        safe_empty_port_release($port);
        safe_empty_port_release($tls_port);
        die $@;
    }
    my $ret = {
        port             => $port,
        tls_port         => $tls_port,
        guard            => $guard,
        pid              => $pid,
        release_ports    => scope_guard(sub {
            safe_empty_port_release($port);
            safe_empty_port_release($tls_port);
        }),
    };
    return $ret;
}

sub create_data_file {
    my $sz = shift;
    my ($fh, $fn) = tempfile(UNLINK => 1);
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

sub run_prog {
    my $cmd = shift;
    my ($tempfh, $tempfn) = tempfile(UNLINK => 1);
    my $stderr = `$cmd 2>&1 > $tempfn`;
    my $stdout = do { local $/; <$tempfh> };
    return ($stderr, $stdout);
}

sub openssl_can_negotiate {
    my $openssl_ver = `openssl version`;
    $openssl_ver =~ /^\S+\s(\d+)\.(\d+)\.(\d+)/
        or die "cannot parse OpenSSL version: $openssl_ver";
    $openssl_ver = $1 * 10000 + $2 * 100 + $3;
    return $openssl_ver >= 10001;
}

sub curl_supports_http2 {
    return !! (`curl --version` =~ /^Features:.*\sHTTP2(?:\s|$)/m);
}

sub run_with_curl {
    my ($server, $cb) = @_;
    plan skip_all => "curl not found"
        unless prog_exists("curl");
    subtest "http/1" => sub {
        $cb->("http", $server->{port}, "curl");
    };
    subtest "https/1" => sub {
        my $cmd = "curl --insecure";
        $cmd .= " --http1.1"
            if curl_supports_http2();
        $cb->("https", $server->{tls_port}, $cmd);
    };
    subtest "https/2" => sub {
        plan skip_all => "curl does not support HTTP/2"
            unless curl_supports_http2();
        $cb->("https", $server->{tls_port}, "curl --insecure --http2");
    };
}

1;
