package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Fcntl qw(:flock);
use File::Temp qw(tempfile tempdir);
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Poll qw(POLLIN POLLOUT POLLHUP POLLERR);
use IPC::Open3;
use List::Util qw(shuffle);
use List::MoreUtils qw(firstidx);
use Net::EmptyPort qw(check_port);
use Net::DNS::Nameserver;
use POSIX ":sys_wait_h";
use Path::Tiny;
use Protocol::HTTP2::Connection;
use Protocol::HTTP2::Constants;
use Scope::Guard;
use Symbol 'gensym';
use Test::More;
use Time::HiRes qw(sleep gettimeofday tv_interval);
use Carp;

use base qw(Exporter);
our @EXPORT = qw(
    ASSETS_DIR
    DOC_ROOT
    bindir
    run_as_root
    server_features
    exec_unittest
    exec_mruby_unittest
    exec_fuzzer
    spawn_server
    spawn_h2o
    spawn_h2o_raw
    empty_port
    empty_ports
    create_data_file
    md5_file
    etag_file
    prog_exists
    run_prog
    openssl_can_negotiate
    openssl_supports_tls13
    curl_supports_http2
    curl_supports_http3
    run_with_curl
    h2get_exists
    run_with_h2get
    run_with_h2get_simple
    spawn_h2get_backend
    one_shot_http_upstream
    wait_debugger
    make_guard
    spawn_forked
    spawn_h2_server
    find_blackhole_ip
    get_tracer
    check_dtrace_availability
    run_picotls_client
    spawn_dns_server
    run_openssl_client
    run_fuzzer
    test_is_passing
    get_exclusive_lock
    debug
);

use constant ASSETS_DIR => 't/assets';
use constant DOC_ROOT   => ASSETS_DIR . "/doc_root";

sub bindir {
    $ENV{H2O_VALGRIND} || $ENV{BINARY_DIR} || '.';
}

sub run_as_root {
    return if $< == 0;
    exec qw(sudo -E env PERL5LIB=.), "PATH=$ENV{PATH}", $^X, $0, @ARGV;
    die "failed to invoke $0 using sudo:$!";
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
            if ($< == 0) {
                exec qw(share/h2o/kill-on-close -- memcached -u root -l 127.0.0.1 -p), $port;
            } else {
                exec qw(share/h2o/kill-on-close -- memcached -l 127.0.0.1 -p), $port;
            }
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

sub exec_fuzzer {
    my $name = shift;
    my $prog = bindir() . "/h2o-fuzzer-$name";

    plan skip_all => "$prog does not exist"
        if ! -e $prog;

    is system("$prog -close_fd_mask=3 -runs=1 -max_len=16384 fuzz/$name-corpus < /dev/null"), 0;
    done_testing;
}

# spawns a child process and returns a guard object that kills the process when destroyed
sub spawn_server {
    my %args = @_;
    my $ppid = $$;
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid != 0) {
        print STDERR "spawning $args{argv}->[0]... ";
        if ($args{is_ready}) {
            for (my $i = 0; !$args{is_ready}->(); ++$i) {
                if (waitpid($pid, WNOHANG) == $pid) {
                    die "server failed to start (got $?)\n";
                }
                die "server failed to boot in 10 seconds\n"
                    if $i > 100;
                sleep 0.1;
            }
            print STDERR "done\n";
        }
        my $guard = make_guard(sub {
            return if $$ != $ppid;
            print STDERR "killing $args{argv}->[0]... ";
            my $sig = 'TERM';
          Retry:
            if (kill $sig, $pid) {
                my $i = 0;
                my $sigterm = sig_num('TERM');
                my $sigkill = sig_num('KILL');
                my $sigzero = sig_num('ZERO');
                while (1) {
                    if (waitpid($pid, WNOHANG) == $pid) {
                        Test::More::fail "server die with signal $?"
                            unless $? == $sigterm || $? == $sigkill || $? == $sigzero;
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

sub sig_num {
    my $name = shift;
    firstidx { $_ eq $name } split " ", $Config::Config{sig_name};
}

# returns a hash containing `port`, `tls_port`, `quic_port`, `guard`
# Set { disable_quic => 1} to disable QUIC support.
sub spawn_h2o {
    my ($conf) = @_;
    my @opts;
    my $max_ssl_version;
    my $disable_quic = ref $conf eq 'HASH' && $conf->{disable_quic};

    # decide the port numbers
    my ($port, $tls_port) = empty_ports(2, { host => "0.0.0.0" });
    my $quic_port;
    my $listen_quic;
    my @all_ports = (
        {
            port => $port,
            proto => 'tcp',
        },
        {
            port => $tls_port,
            proto => 'tcp',
        },
    );

    if (!$disable_quic) {
        $quic_port = empty_port({ host => "0.0.0.0", proto => "tcp" });
        push @all_ports, {
            port => $quic_port,
            proto => 'udp',
        };
        $listen_quic = <<"EOT";
  - type: quic
    host: 0.0.0.0
    port: $quic_port
    ssl:
      key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
EOT
    }

    # setup the configuration file
    $conf = $conf->($port, $tls_port, $quic_port)
        if ref $conf eq 'CODE';
    my $user = $< == 0 ? "root" : "";
    if (ref $conf eq 'HASH') {
        @opts = @{$conf->{opts}}
            if $conf->{opts};
        $max_ssl_version = $conf->{max_ssl_version} || undef;
        $user = $conf->{user} if exists $conf->{user};
        push @all_ports, $conf->{extra_ports} if exists $conf->{extra_ports};
        $conf = $conf->{conf};
    }
    $conf = <<"EOT";
$conf
listen:
  - host: 0.0.0.0
    port: $port
  - host: 0.0.0.0
    port: $tls_port
    ssl:
      key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
      @{[$max_ssl_version ? "max-version: $max_ssl_version" : ""]}
$listen_quic
@{[$user ? "user: $user" : ""]}
EOT

    my $ret = spawn_h2o_raw($conf, \@all_ports, \@opts);
    return {
        %$ret,
        port => $port,
        tls_port => $tls_port,
        quic_port => $quic_port,
    };
}

sub spawn_h2o_raw {
    my ($conf, $check_ports, $opts) = @_;

    # By default, h2o will launch as many threads as there are CPU cores on the
    # host, unless 'num-threads' is specified. This results in the process
    # running out of file descriptors, if the 'nofiles' limit is low and the
    # host has a large number of CPU cores. So make sure the number of threads
    # is bound.
    $conf = "num-threads: 2\n$conf" unless $conf =~ /^num-threads:/m;

    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    print $conffh $conf or confess("failed to write to $conffn: $!");
    $conffh->flush or confess("failed to write to $conffn: $!");
    debug($conf);

    # spawn the server
    my ($guard, $pid) = spawn_server(
        argv     => [ bindir() . "/h2o", "-c", $conffn, @{$opts || []} ],
        is_ready => sub {
            check_port($_) or return for @{ $check_ports || [] };
            1;
        },
    );
    return {
        guard    => $guard,
        pid      => $pid,
        conf_file => $conffn,
    };
}

sub empty_port_using_file {
    my ($host, $port, $proto) = @_;
    my $fn = $ENV{NET_EMPTYPORT_SRCFILE};

    # lock-open the source file, and read the last port number
    open my $fh, '+>>', $fn
        or die "failed to open file:$fn:$!";
    flock $fh, LOCK_EX
        or die "failed to lock file:$fn:$!";
    seek $fh, 0, 0
        or die "failed to seek file:$fn:$!";
    $port = <$fh>
        unless $port;
    $port ||= 65535; # if failed to read, start with an invalid number (see below)
    # find the next available port
    for (my $fail_cnt = 0;; ++$fail_cnt) {
        $port += 2;
        $port = 32769 if $port > 49152;
        last if Net::EmptyPort::can_bind($host, $port, $proto);
        die "empty port not found"
            if $fail_cnt >= 100;
    }
    # write the last port number to file
    seek $fh, 0, 0
        or die "failed to seek file:$fn:$!";
    truncate $fh, 0
        or die "failed to trancate file:$fn:$!";
    print $fh $port;
    # close file (and unlock implicitly)
    close $fh;

    $port;
}

sub empty_port {
    my ($host, $port, $proto) = @_ && ref $_[0] eq 'HASH' ? ($_[0]->{host}, $_[0]->{port}, $_[0]->{proto}) : (undef, @_);
    $host = '127.0.0.1'
        unless defined $host;
    $proto = $proto ? lc($proto) : 'tcp';

    my $found;

    for (my $fail_cnt = 0;; ++$fail_cnt) {
        if ($ENV{NET_EMPTYPORT_SRCFILE}) {
            $found = empty_port_using_file($host, $port, $proto);
        } else {
            $found = Net::EmptyPort::empty_port({host => $host, port => $port, proto => $proto});
        }
        # finally check that $cand can be bound on addresses 0.0.0.0 and 127.0.0.1, as there are rules to prefer one over another
        # and we do not want that rule to kick in
        last unless grep { $_ ne $host && !Net::EmptyPort::can_bind($_, $found, $proto) } qw(0.0.0.0 127.0.0.1);
        $port = $found; # set $port to indicate the last port we failed on
        die "empty port not found"
            if $fail_cnt >= 100;
    }

    $found;
}

sub empty_ports {
    my ($n, @ep_args) = @_;
    my @ports;
    while (@ports < $n) {
        my $t = empty_port(@ep_args);
        push @ports, $t
            unless grep { $_ == $t } @ports;
    }
    return @ports;
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

sub etag_file {
    my $fn = shift;
    my @st = stat $fn
        or die "failed to stat file:$fn:$!";
    return sprintf("\"%08x-%zx\"", $st[9], $st[7]);
}

sub prog_exists {
    my $prog = shift;
    # if SKIP_PROG_EXISTS environment variable is set (e.g., in case of running on CI image), all programs are assumed to exist
    return 1
        if $ENV{SKIP_PROG_EXISTS};
    system("which $prog > /dev/null 2>&1") == 0;
}

sub run_prog {
    my $cmd = shift;
    my ($tempfh, $tempfn) = tempfile(UNLINK => 1);
    my $stderr = `$cmd 2>&1 > $tempfn`;
    my $stdout = do { local $/; <$tempfh> };
    close $tempfh; # tempfile does not close the file automatically (see perldoc)
    return ($stderr, $stdout);
}

sub openssl_can_negotiate {
    my $openssl_ver = `openssl version`;
    $openssl_ver =~ /^\S+\s(\d+)\.(\d+)\.(\d+)/
        or die "cannot parse OpenSSL version: $openssl_ver";
    $openssl_ver = $1 * 10000 + $2 * 100 + $3;
    return $openssl_ver >= 10001;
}

sub openssl_supports_tls13 {
    return 1 if $ENV{SKIP_PROG_EXISTS};
    return !!( `openssl s_client -help 2>&1` =~ /^\s*-tls1_3\s+/m);
}

sub curl_supports_http2 {
    return 1 if $ENV{SKIP_PROG_EXISTS};
    return !! (`curl --version` =~ /^Features:.*\sHTTP2(?:\s|$)/m);
}

sub curl_supports_http3 {
    return 1 if $ENV{SKIP_PROG_EXISTS};
    return !! (`curl --version` =~ /^Features:.*\sHTTP3(?:\s|$)/m);
}

sub run_with_curl {
    my ($server, $cb) = @_;
    plan skip_all => "curl not found"
        unless prog_exists("curl");
    subtest "http/1" => sub {
        $cb->("http", $server->{port}, "curl", 257);
    };
    subtest "https/1" => sub {
        my $cmd = "curl --insecure";
        $cmd .= " --http1.1"
            if curl_supports_http2();
        $cb->("https", $server->{tls_port}, $cmd, 257);
    };
    subtest "https/2" => sub {
        plan skip_all => "curl does not support HTTP/2"
            unless curl_supports_http2();
        $cb->("https", $server->{tls_port}, "curl --insecure --http2", 512);
    };
    subtest "https/3" => sub {
        plan skip_all => "curl does not support HTTP/3"
            unless curl_supports_http3();
        plan skip_all => "\$server does not have quic_port set"
            unless $server->{quic_port};
        $cb->("https", $server->{quic_port}, "curl --insecure --http3", 768);
    };
}

sub h2get_exists {
    prog_exists(bindir() . "/h2get_bin/h2get");
}

sub run_with_h2get {
    my ($server, $script) = @_;
    plan skip_all => "h2get not found"
        unless h2get_exists();
    my $helper_code = <<"EOR";
class H2
    def read_loop(timeout)
        while true
            f = self.read(timeout)
            return nil if f == nil
            if block_given?
                yield f
            else
                puts f.to_s
            end
            if f.type == "DATA" && f.len > 0
                self.send_window_update(0, f.len)
                self.send_window_update(f.stream_id, f.len)
            end
            if (f.type == "DATA" || f.type == "HEADERS") && f.is_end_stream
                return f
            elsif f.type == "RST_STREAM" || f.type == "GOAWAY"
                return f
            end
        end
    end
end
EOR
    $script = "$helper_code\n$script";
    my ($scriptfh, $scriptfn) = tempfile(UNLINK => 1);
    print $scriptfh $script;
    close($scriptfh);
    return run_prog(bindir()."/h2get_bin/h2get $scriptfn 127.0.0.1:$server->{tls_port}");
}

sub run_with_h2get_simple {
    my ($server, $script) = @_;
    my $settings = <<'EOS';
    h2g = H2.new
    authority = ARGV[0]
    host = "https://#{authority}"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings()
    i = 0
    while i < 2 do
        f = h2g.read(-1)
        if f.type == "SETTINGS" and (f.flags == ACK) then
            i += 1
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
            i += 1
        end
    end
EOS
    run_with_h2get($server, $settings."\n".$script);
}

sub one_shot_http_upstream {
    my ($response, $port) = @_;
    my $listen = IO::Socket::INET->new(
        LocalHost => '0.0.0.0',
        LocalPort => $port,
        Proto     => 'tcp',
        Listen    => 1,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$port:$!";

    my $pid = fork;
    die "fork failed" unless defined $pid;
    if ($pid != 0) {
        close $listen;
        my $guard = make_guard(sub {
            kill 'KILL', $pid;
            while (waitpid($pid, WNOHANG) != $pid) {}
        });
        return ($port, $guard);
    }

    while (my $sock = $listen->accept) {
        $sock->print($response);
        close $sock;
    }
}

sub wait_debugger {
    my ($pid, $timeout) = @_;
    $timeout ||= -1;

    print STDERR "waiting debugger for pid $pid ..\n";
    while ($timeout-- != 0) {
        my $out = `ps -p $pid -o 'state' | tail -n 1`;
        if ($out =~ /^(T|.+X).*$/) {
            print STDERR "debugger attached\n";
            return 1;
        }
        sleep 1;
    }
    print STDERR "no debugger attached\n";
    undef;
}

sub make_guard {
    my $code = shift;
    return Scope::Guard->new(sub {
        local $?;
        $code->();
    });
}

sub spawn_forked {
    my ($code, $opts) = @_;
    $opts = +{
        stdout => 1,
        stderr => 0,
        %{ $opts || +{} }
    };

    my $tempdir = File::Temp::tempdir(CLEANUP => 1) if $opts->{stdout} || $opts->{stderr};

    my $pid = fork;
    if ($pid) {
        my $wait = sub {
            while (waitpid($pid, 0) != $pid) {}
            undef $pid;
        };
        my $guard = make_guard(sub {
            return unless defined $pid;
            kill 'TERM', $pid;
            $wait->();
        });
        my $read_outputs = sub {
            my $out = path("$tempdir/out")->slurp if $opts->{stdout};
            my $err = path("$tempdir/err")->slurp if $opts->{stderr};
            ($out, $err)
        };
        return +{
            pid => $pid,
            wait => sub {
                $wait->();
                $read_outputs->()
            },
            kill => sub {
                undef $guard;
                $read_outputs->()
            },
        };
    }
    if ($opts->{stdout}) {
        open(STDOUT, '>', "$tempdir/out") or die $!;
    }
    if ($opts->{stderr}) {
        open(STDERR, '>', "$tempdir/err") or die $!;
    }

    $code->();
    exit;
}

sub spawn_h2_server {
    my ($upstream_port, $stream_state_cbs, $stream_frame_cbs) = @_;

    my $upstream = IO::Socket::SSL->new(
        LocalAddr => '127.0.0.1',
        LocalPort => $upstream_port,
        Listen => 1,
        ReuseAddr => 1,
        SSL_cert_file => 'examples/h2o/server.crt',
        SSL_key_file => 'examples/h2o/server.key',
        SSL_alpn_protocols => ['h2'],
    ) or die "cannot create socket: $!";

    my $server = spawn_forked(sub {
        my $conn; $conn = Protocol::HTTP2::Connection->new(Protocol::HTTP2::Constants::SERVER,
            on_new_peer_stream => sub {
                my $stream_id = shift;
                for my $state (keys %{ $stream_state_cbs || +{} }) {
                    my $cb = $stream_state_cbs->{$state};
                    $conn->stream_cb($stream_id, $state, sub {
                        $cb->($conn, $stream_id);
                    });
                }
                for my $type (keys %{ $stream_frame_cbs || +{} }) {
                    my $cb = $stream_frame_cbs->{$type};
                    $conn->stream_frame_cb($stream_id, $type, sub {
                        $cb->($conn, $stream_id, shift);
                    });
                }
            },
        );
        $conn->{_state} = +{};
        $conn->enqueue(Protocol::HTTP2::Constants::SETTINGS, 0, 0, +{});
        my $sock = $upstream->accept or die "cannot accept socket: $!";

        my $input = '';
        while (!$conn->{_state}->{closed}) {
            my $offset = 0;
            my $buf;
            my $r = $sock->read($buf, 1);
            next unless $r;
            $input .= $buf;

            unless ($conn->preface) {
                my $len = $conn->preface_decode(\$input, 0);
                unless (defined($len)) {
                    die 'invalid preface';
                }
                next unless $len;
                $conn->preface(1);
                $offset += $len;
            }

            while (my $len = $conn->frame_decode(\$input, $offset)) {
                $offset += $len;
            }
            substr($input, 0, $offset) = '' if $offset;

            if (my $after_read = delete($conn->{_state}->{after_read})) {
                $after_read->();
            }

            while (my $frame = $conn->dequeue) {
                $sock->write($frame);
            }

            if (my $after_write = delete($conn->{_state}->{after_write})) {
                $after_write->();
            }
        }
    });

    close $upstream;
    return $server;
}

sub spawn_h2get_backend {
    my $h2_snippet = shift;
    my $testfn = shift;
    my ($backend_port) = empty_ports(1, { host => '0.0.0.0' });
    my $backend = spawn_forked(sub {
        my $code = <<"EOC";
STDOUT.sync = true
h2g = H2.server({
    'cert_path' => 'examples/h2o/server.crt',
    'key_path' => 'examples/h2o/server.key',
});
h2g.listen("https://127.0.0.1:$backend_port")

connpool = {}

loop do
  begin
    conn = h2g.accept(100)
  rescue => e
  end
  if conn
    connpool[conn] = true;
    conn.expect_prefix
    conn.send_settings([])

    loop do
      f = conn.read(-1)
      if f.type == 'SETTINGS'
        unless f.flags == ACK then
          conn.send_settings_ack()
          break
        end
      else
        raise 'oops'
      end
    end
  end
  connpool.keys.each do |conn|
    loop do
      begin
        f = conn.read(1000)
      rescue => e
        # passive close
        conn.close
        connpool.delete(conn)
        break
      end
      break if f.nil? # timeout
      $h2_snippet
    end
  end
end
EOC
        my ($scriptfh, $scriptfn) = tempfile(UNLINK => 1);
        print $scriptfh $code;
        close($scriptfh);
        exec(bindir() . '/h2get_bin/h2get', $scriptfn, "127.0.0.1:$backend_port");
    }, +{ stderr => 1 });

    $backend->{tls_port} = $backend_port;
    return $backend;
}
# usage: see t/90h2olog.t
package H2ologTracer {
    use POSIX ":sys_wait_h";

    sub new {
        my ($class, $opts) = @_;
        unless ($opts->{path}) {
            Carp::croak("Missing path in the opts (pid is no longer supported)");
        }
        my $h2olog_socket_path = $opts->{path};
        my $h2olog_args = $opts->{args} // [];
        my $output_dir = $opts->{output_dir} // File::Temp::tempdir(CLEANUP => 1);

        my $h2olog_prog = "misc/h2olog";

        my $output_file = "$output_dir/h2olog.jsonl";
        my $attaching_opts = "-u $h2olog_socket_path";

        my $tracer_pid = open my($errfh), "-|", qq{exec $h2olog_prog @{$h2olog_args} -d $attaching_opts -w '$output_file' 2>&1};
        die "failed to spawn $h2olog_prog: $!" unless defined $tracer_pid;

        # wait until h2olog and the trace log becomes ready
        while (1) {
            my $errline = <$errfh>;
            Carp::confess("h2olog[$tracer_pid] died unexpectedly")
                unless defined $errline;
            Test::More::diag("h2olog[$tracer_pid]: $errline");
            last if $errline =~ /\bAttaching\b/ms;
        }

        open my $fh, "<", $output_file or die "h2olog[$tracer_pid] does not create the output file ($output_file): $!";
        my $off = 0;
        my $get_trace = sub {
            Carp::confess "h2olog[$tracer_pid] is down (got $?)"
                if waitpid($tracer_pid, WNOHANG) != 0;

            seek $fh, $off, 0 or die "seek failed: $!";
            read $fh, my $bytes, 65000;
            $bytes = ''
                unless defined $bytes;
            $off += length $bytes;
            return $bytes;
        };

        my $guard = t::Util::make_guard(sub {
            if (waitpid($tracer_pid, WNOHANG) == 0) {
                Test::More::diag "killing h2olog[$tracer_pid] with SIGTERM";
                kill("TERM", $tracer_pid)
                    or warn("failed to kill h2olog[$tracer_pid]: $!");
            } else {
                Test::More::diag($_) while <$errfh>; # in case h2olog shows error messages, e.g. BPF program doesn't compile
                Test::More::diag "h2olog[$tracer_pid] has already exited";
            }
        });

        return bless {
            _guard => $guard,
            tracer_pid => $tracer_pid,
            get_trace => $get_trace,
            output_dir => $output_dir,
            output_file => $output_file,
        }, $class;
    }

    sub get_trace {
        my($self) = @_;
        return $self->{get_trace}->();
    }
}

sub find_blackhole_ip {
    my %ips;
    my $port = $_[0] || 23;
    my $blackhole_ip = undef;
    my $poll = IO::Poll->new();
    my $start = [ gettimeofday() ];

    foreach my $ip ('10.0.0.1', '192.168.0.1', '172.16.0.1', '240.0.0.1', '192.0.2.0') {
        my $sock = IO::Socket::INET->new(Blocking => 0, PeerPort => $port, PeerAddr => $ip);
        $ips{$sock} = $ip;
        $poll->mask($sock => POLLOUT|POLLIN|POLLERR|POLLHUP);
    }
    while (scalar($poll->handles()) > 0 and tv_interval($start) < 2.00) {
        if ($poll->poll(.1) > 0) {
            foreach my $sock ($poll->handles(POLLOUT|POLLIN|POLLERR|POLLHUP)) {
                delete($ips{$sock});
                $poll->remove($sock);
                $sock->close()
            }
        }
    }
    if (scalar($poll->handles()) > 0) {
        $blackhole_ip = $ips{(keys %ips)[rand(keys %ips)]}
    }
    foreach my $sock ($poll->handles()) {
        $poll->remove($sock);
        $sock->close();
    }
    die unless $poll->handles() == 0;
    return $blackhole_ip;
}

sub check_dtrace_availability {
    run_as_root();

    plan skip_all => 'dtrace support is off'
        unless server_features()->{dtrace};

    if ($^O eq 'linux') {
        plan skip_all => 'bpftrace not found'
            unless prog_exists('bpftrace');
        # NOTE: the test is likely to depend on https://github.com/iovisor/bpftrace/pull/864
        plan skip_all => "skipping bpftrace tests (setenv DTRACE_TESTS=1 to run them)"
            unless $ENV{DTRACE_TESTS};
    } else {
        plan skip_all => 'dtrace not found'
            unless prog_exists('dtrace');
        plan skip_all => 'unbuffer not found'
            unless prog_exists('unbuffer');
    }
}

sub get_tracer {
    my $tracer_pid = shift;
    my $fn = shift;
    my $read_trace;

    while (!-e $fn) {
        die "tracer failed to start\n"
            if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
        sleep 0.1;
    }

    open my $fh, '-|', 'tail', '-c', '+1', '-f', $fn
        or die "failed invoke tail opening $fn:$?";

    return sub {
        IO::Select->new($fh)->can_read(1);
        sysread $fh, my $bytes, 1048576;
        $bytes = ''
            unless defined $bytes;
        if ($bytes eq '' && waitpid($tracer_pid, WNOHANG) == $tracer_pid) {
            die "tracer died with status $? and there would be no more data";
        }
        $bytes;
    };
}

sub run_picotls_client {
    my($opts) = @_;
    my $port = $opts->{port}; # required
    my $host = $opts->{host} // '127.0.0.1';
    my $path = $opts->{path} // '/';
    my $cli_opts = $opts->{opts} // '';

    my $cli = bindir() . "/picotls/cli";

    my $tempdir = tempdir();
    my $cmd = "exec $cli $cli_opts $host $port > $tempdir/resp.txt 2>&1";
    diag $cmd;
    open my $fh, "|-", $cmd
        or die "failed to invoke command:$cmd:$!";
    autoflush $fh 1;
    print $fh <<"EOT";
GET $path HTTP/1.1\r
Host: $host:$port\r
Connection: close\r
\r
EOT
    sleep 1;
    close $fh;

    open $fh, "<", "$tempdir/resp.txt"
        or die "failed to open file:$tempdir/resp.txt:$!";
    my $resp = do { local $/; <$fh> };
    return $resp;
}

sub spawn_dns_server {
    my ($dns_port, $zone_rrs, $delays) = @_;

    my $ns = Net::DNS::Nameserver->new(
        LocalPort    => $dns_port,
        ReplyHandler => sub {
            my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;
            my ($rcode, @ans, @auth, @add);

            foreach (@$zone_rrs) {
                my $rr = Net::DNS::RR->new($_);
                if ($rr->owner eq $qname && $rr->class eq $qclass && $rr->type eq $qtype) {
                    push @ans, $rr;
                }
            }

            if (!@ans) {
                $rcode = "NXDOMAIN";
            } else {
                $rcode = "NOERROR";
            }
            # mark the answer as authoritative (by setting the 'aa' flag)
            my $headermask = {aa => 1};
            my $optionmask = {};
            if ($delays && $delays->{$qtype} > 0) {
                sleep($delays->{$qtype});
            }
            @ans = shuffle(@ans);
            return ($rcode, \@ans, \@auth, \@add, $headermask, $optionmask);
        },
        Verbose      => 0
    ) || die "couldn't create nameserver object\n";

    my $server = spawn_forked(sub {
        $ns->main_loop;
    });

    return $server;
}

sub run_openssl_client {
    my($opts) = @_;
    my $port = $opts->{port} or croak("`port` is required!");
    my $san = $opts->{san};
    my $host = $opts->{host} // '127.0.0.1';
    my $path = $opts->{path} // '/';
    my $timeout = $opts->{timeout} // 2.0;
    my $request = $opts->{request};
    my $request_default = $opts->{request_default} // undef;
    my $ossl_opts = $opts->{opts} // '';
    my $ossl_cmd = $opts->{ossl_cmd} // 'openssl';
    my $split_return = $opts->{split_return} // undef;

    my $cmd = "$ossl_cmd s_client $ossl_opts -connect $host:$port";
    if (defined $san && $san ne '') {
        $cmd = $cmd." -servername $san";
    }
    diag("run_openssl_client: $cmd");

    my $cpid = open3(my $chld_in, my $chld_out, my $chld_err = gensym, $cmd);
    $chld_in->autoflush(1);

    {
        local $SIG{PIPE} = 'IGNORE';

        if ($request_default) {
            print $chld_in <<"EOT";
GET $path HTTP/1.1\r
Host: $san:$port\r
Connection: close\r
\r
EOT
        } elsif (defined $request && $request ne '') {
            print $chld_in "$request";
        }
    }

    while ($timeout > 0.0) {
        my $cpid_wait = waitpid($cpid, POSIX::WNOHANG);
        if ($cpid_wait == $cpid || $cpid_wait == -1) {
            last;
        }

        sleep 0.1;
        $timeout -= 0.1
    }

    close $chld_in;
    my $resp_out = do { local $/; <$chld_out> };
    my $resp_err = do { local $/; <$chld_err> };
    close $chld_out;
    close $chld_err;

    if ($timeout <= 0.0) {
        kill 'KILL', $cpid;
    }

    if ($split_return) {
        return ($resp_out, $resp_err);
    }

    return join("\n", ($resp_out, $resp_err));
}

sub test_is_passing {
    Test::More->builder->is_passing;
}

sub get_exclusive_lock {
    if (! defined $ENV{LOCKFD}) {
        warn "not taking lock, as LOCKFD is not set\n";
        return;
    }
    return if $ENV{LOCKFD} eq "SKIP";

    # open lockfile
    my $lockfh = IO::Handle->new();
    $lockfh->fdopen($ENV{LOCKFD}, "w")
        or die "failed to open file descriptor $ENV{LOCKFD}:$!";
    print STDERR "taking exclusive lock...\n";
    STDERR->flush;

    # Unlock before taking an exclusive lock, otherwise we might deadlock when two processes that have already taken LOCK_SH
    # competes for LOCK_EX.
    flock($lockfh, LOCK_UN)
        or die "flock(LOCK_UN) failed:$!";
    flock($lockfh, LOCK_EX)
        or die "flock(LOCK_EX) failed:$!";
    print STDERR "lock taken\n";
    STDERR->flush;

    # prevent waring above when trying to lock again
    $ENV{LOCKFD} = "SKIP";
}

sub debug {
    return unless $ENV{TEST_DEBUG};
    Test::More::diag(@_);
}

1;
