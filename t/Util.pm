package t::Util;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Poll qw(POLLIN POLLOUT POLLHUP POLLERR);
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Path::Tiny;
use Protocol::HTTP2::Connection;
use Protocol::HTTP2::Constants;
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep gettimeofday tv_interval);

use base qw(Exporter);
our @EXPORT = qw(ASSETS_DIR DOC_ROOT bindir run_as_root server_features exec_unittest exec_mruby_unittest spawn_server spawn_h2o spawn_h2o_raw empty_ports create_data_file md5_file prog_exists run_prog openssl_can_negotiate curl_supports_http2 run_with_curl h2get_exists run_with_h2get run_with_h2get_simple one_shot_http_upstream wait_debugger spawn_forked spawn_h2_server find_blackhole_ip get_tracer check_dtrace_availability);

use constant ASSETS_DIR => 't/assets';
use constant DOC_ROOT   => ASSETS_DIR . "/doc_root";

sub bindir {
    $ENV{H2O_VALGRIND} || $ENV{BINARY_DIR} || '.';
}

sub run_as_root {
    return if $< == 0;
    exec qw(sudo -E env PERL5LIB=.), $^X, $0;
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
            return if $$ != $ppid;
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
    my $max_ssl_version;

    # decide the port numbers
    my ($port, $tls_port) = empty_ports(2, { host => "0.0.0.0" });

    # setup the configuration file
    $conf = $conf->($port, $tls_port)
        if ref $conf eq 'CODE';
    if (ref $conf eq 'HASH') {
        @opts = @{$conf->{opts}}
            if $conf->{opts};
        $max_ssl_version = $conf->{max_ssl_version} || undef;
        $conf = $conf->{conf};
    }
    $conf = <<"EOT";
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
    @{[$max_ssl_version ? "max-version: $max_ssl_version" : ""]}
@{[$< == 0 ? "user: root" : ""]}
EOT

    my $ret = spawn_h2o_raw($conf, [$port, $tls_port], \@opts);
    return {
        %$ret,
        port => $port,
        tls_port => $tls_port,
    };
}

sub spawn_h2o_raw {
    my ($conf, $check_ports, $opts) = @_;

    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    print $conffh $conf;

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

sub prog_exists {
    my $prog = shift;
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

sub curl_supports_http2 {
    return !! (`curl --version` =~ /^Features:.*\sHTTP2(?:\s|$)/m);
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
            puts f.to_s
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
        my $guard = scope_guard(sub {
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

sub spawn_forked {
    my ($code) = @_;

    my ($cout, $pin);
    pipe($pin, $cout);
    my ($cerr, $pin2);
    pipe($pin2, $cerr);

    my $pid = fork;
    if ($pid) {
        close $cout;
        close $cerr;
        my $upstream; $upstream = +{
            pid => $pid,
            kill => sub {
                return unless defined $pid;
                kill 'KILL', $pid;
                undef $pid;
            },
            guard => Scope::Guard->new(sub { $upstream->{kill}->() }),
            stdout => $pin,
            stderr => $pin2,
        };
        return $upstream;
    }
    close $pin;
    close $pin2;
    open(STDOUT, '>&=', fileno($cout)) or die $!;
    open(STDERR, '>&=', fileno($cerr)) or die $!;

    $code->();
    exit;
}

sub spawn_h2_server {
    my ($upstream_port, $stream_state_cbs, $stream_frame_cbs) = @_;
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
        my $upstream = IO::Socket::SSL->new(
            LocalAddr => '127.0.0.1',
            LocalPort => $upstream_port,
            Listen => 1,
            ReuseAddr => 1,
            SSL_cert_file => 'examples/h2o/server.crt',
            SSL_key_file => 'examples/h2o/server.key',
            SSL_alpn_protocols => ['h2'],
        ) or die "cannot create socket: $!";
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
    return $server;
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
    while (1) {
        sleep 1;
        if (open my $fh, "<", $fn) {
            my $off = 0;
            $read_trace = sub {
                seek $fh, $off, 0
                    or die "seek failed:$!";
                read $fh, my $bytes, 1048576;
                $bytes = ''
                    unless defined $bytes;
                $off += length $bytes;
                if ($^O ne 'linux') {
                    $bytes = join "", map { substr($_, 4) . "\n" } grep /^XXXX/, split /\n/, $bytes;
                }
                return $bytes;
            };
            last;
        }
        die "bpftrace failed to start\n"
            if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
    }
    return $read_trace;
}

1;
