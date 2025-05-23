use strict;
use warnings;
use File::Basename;
use File::Temp qw(tempfile);
use Test::More;
use t::Util;

run_as_root();

#
# https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/tree/tools/testing/selftests/net/busy_poll_test.sh
#

plan skip_all => "netdevsim kernel module not available"
unless system("modprobe netdevsim") == 0;

ok(prog_exists("udevadm"), "have udevadm");

my $nsim_sv_id = 256 + int(rand(256));
my $nsim_cl_id = 512 + int(rand(256));
my $nsim_sv_fd;
my $nsim_cl_fd;
my $nsim_sv_ifidx;
my $nsim_cl_ifidx;
my $nsim_sv_name;
my $nsim_cl_name;

my $nsim_sv_ports = 1;
my $nsim_sv_queues = 4;
my $nsim_sv_sys = "/sys/bus/netdevsim/devices/netdevsim$nsim_sv_id";
my $nsim_cl_sys = "/sys/bus/netdevsim/devices/netdevsim$nsim_cl_id";
my $nsim_dev_sys_new = "/sys/bus/netdevsim/new_device";
my $nsim_dev_sys_del = "/sys/bus/netdevsim/del_device";
my $nsim_dev_sys_link = "/sys/bus/netdevsim/link_device";
my $nsim_dev_sys_unlink = "/sys/bus/netdevsim/unlink_device";

my $server_ip = "192.168.1.1";
my $client_ip = "192.168.1.2";

subtest "busypoller" => sub {
    cleanup_ns();
    create_devices();
    setup_ns();
    link_devices();
    ok(test_busypoll('OFF', $nsim_sv_queues) == 0, "busypoll off");
    ok(test_busypoll('BUSYPOLL', $nsim_sv_queues) == 0, "always busypoll");
    ok(test_busypoll('SUSPEND', $nsim_sv_queues) == 0, "suspend mode");
    unlink_devices();
    cleanup_ns();
    ok(system("modprobe -r netdevsim") == 0, "unload netdevsim");
};

done_testing;

sub find_device_name {
    my $sys_path = shift;
    my @devices = glob("$sys_path/net/*");
    return basename($devices[0]);
}   

sub create_devices() {
    # both server/client should have the same number of queues since the outgoing queue will be used as the incoming queue
    ok(system("echo '$nsim_sv_id $nsim_sv_ports $nsim_sv_queues' > $nsim_dev_sys_new") == 0, "new server device");
    ok(system("echo '$nsim_cl_id $nsim_sv_ports $nsim_sv_queues' > $nsim_dev_sys_new") == 0, "new client device");
    ok(system("udevadm settle") == 0, "udevadm settle ok");
}

sub link_devices() {
    $nsim_sv_fd = POSIX::open("/var/run/netns/nssv", POSIX::O_RDONLY);
    $nsim_cl_fd = POSIX::open("/var/run/netns/nscl", POSIX::O_RDONLY);
    $nsim_sv_ifidx = `ip netns exec nssv cat /sys/class/net/$nsim_sv_name/ifindex`;
    $nsim_cl_ifidx = `ip netns exec nscl cat /sys/class/net/$nsim_cl_name/ifindex`;
    chomp($nsim_sv_ifidx);
    chomp($nsim_cl_ifidx);
    ok(system("echo \"$nsim_sv_fd:$nsim_sv_ifidx $nsim_cl_fd:$nsim_cl_ifidx\" > $nsim_dev_sys_link") == 0, "linking netdevsim1 with netdevsim2 should succeed");
}

sub unlink_devices() {
    system("echo \"$nsim_sv_fd:$nsim_sv_ifidx\" > $nsim_dev_sys_unlink");
    system("echo $nsim_cl_id > $nsim_dev_sys_del");
    POSIX::close($nsim_sv_fd);
    POSIX::close($nsim_cl_fd);
}

sub setup_ns {
    ok(system("ip netns add nssv") == 0, "add server namespace");
    ok(system("ip netns add nscl") == 0, "add client namespace");

    $nsim_sv_name = find_device_name($nsim_sv_sys);
    $nsim_cl_name = find_device_name($nsim_cl_sys);

    ok(defined $nsim_sv_name && length $nsim_sv_name, "server iface set - $nsim_sv_name");
    ok(defined $nsim_cl_name && length $nsim_cl_name, "client iface set - $nsim_cl_name");

    ok(system("ip link set $nsim_sv_name netns nssv") == 0, "server iface moved to server ns");
    ok(system("ip link set $nsim_cl_name netns nscl") == 0, "client iface moved to client ns");

    ok(system("ip netns exec nssv ip addr add \"$server_ip/24\" dev $nsim_sv_name") == 0, "server ip assigned");
    ok(system("ip netns exec nscl ip addr add \"$client_ip/24\" dev $nsim_cl_name") == 0, "client ip assigned");

    ok(system("ip netns exec nssv ip link set dev lo up") == 0, "server loopback up");
    ok(system("ip netns exec nssv ip link set dev $nsim_sv_name up") == 0, "server iface up");
    ok(system("ip netns exec nscl ip link set dev $nsim_cl_name up") == 0, "client iface up");
}

sub cleanup_ns {
    system("ip netns del nscl 2>/dev/null");
    system("ip netns del nssv 2>/dev/null");
}

sub get_busypoll_rx_packets {
    my $nstat = `ip netns exec nssv cat /proc/net/netstat`;
    my @lines = split("\n", $nstat);
    my ($keys, $values);
    foreach (@lines) {
        if (/^TcpExt:/) {
            if (!$keys) {
                $keys = $_;
                $keys =~ s/^TcpExt:\s*//;
                $keys = [split /\s+/, $keys];
            } else {
                $values = $_;
                $values =~ s/^TcpExt:\s*//;
                $values = [split /\s+/, $values];
                last;
            }
        }
    }
    my %hash;
    @hash{@$keys} = @$values;
    return $hash{BusyPollRxPackets};
}

sub test_busypoll {
    my $mode = shift // 'OFF';
    my $num_threads = shift // 1;
    my ($usecs, $budget, $gro_flush_timeout, $defer_hard_irqs, $suspend_timeout) = (0, 0, 0, 0, 0);

    $mode = 'OFF' unless $mode =~ /^(BUSYPOLL|SUSPEND)$/;
    if ($mode eq "BUSYPOLL") {
        $usecs = 1000;
        $budget = 16;
        $gro_flush_timeout =  90000000;
        $defer_hard_irqs =  100;
    } elsif ($mode eq "SUSPEND") {
        $usecs = 0;
        $gro_flush_timeout =  90000000;
        $defer_hard_irqs = 100;
        $suspend_timeout = 180000000;
    }

    my ($port) = empty_ports(1, { host => "0.0.0.0" });
    my $cpu_list = '[' . join(', ', 1..$num_threads) . ']';
    my $total_threads = $num_threads + 1;
    (my $ah, my $access_log) = tempfile(UNLINK => 1);
    my $h2o_sv = spawn_h2o_raw(<< "EOT", [], [], {'namespace' => 'nssv' });
listen:
  host: 0.0.0.0
  port: $port
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
    access-log:
      path: $access_log
      format: "%{bp.iface}x %{bp.napi-id}x %{bp.cpu-idx}x %{thread-index}x"

capabilities:
  - CAP_NET_ADMIN
tcp-reuseport: ON
num-threads: $total_threads

epoll-nonblock: ON
busy-poll-budget: $budget
busy-poll-usecs: $usecs

busy-poll-map:
  interfaces:
    - ifindex: 1
      cpus: [0]
      options:
        mode: OFF
    - ifindex: $nsim_sv_ifidx
      cpus: $cpu_list
      options:
        gro-flush-timeout: $gro_flush_timeout
        defer-hard-irqs: $defer_hard_irqs
        suspend-timeout: $suspend_timeout
        mode: $mode
EOT

    # h2o was spawned without a port for the is_ready check as it would fail in a namespace
    sleep(1); # intead we sleep for a bit


    my $ss_out = `ip netns exec nssv ss -tlnp`;
    diag("LISTENERS:\n" . $ss_out);

    my $bprx = get_busypoll_rx_packets();

    for (1..5) {
        my $resp = `ip netns exec nssv curl -ksi http://127.0.0.1:$port`;
    }

    my $num_attempts = 3000;
    for (1..$num_attempts) {
        my $resp = `ip netns exec nscl curl -ksi -XPOST -F \"file=\@t/assets/doc_root/halfdome.jpg" http://$server_ip:$port`;
        #like $resp, qr{^HTTP/1.1 200 OK\r\n}s, "curl request ok";
    }
    for (1..5) {
        my $resp = `ip netns exec nssv curl -ksi http://127.0.0.1:$port`;
    }

    my %served;
    while (my $line = <$ah>) {
        chomp $line;
        $served{$line}++;
    }

    is(scalar keys %served, $total_threads, "$total_threads thread(s) served all requests");
    while (my ($served_by, $count) = each %served) {
        my ($served_iface, $served_napi, $served_cpu, $served_thread) = split ' ', $served_by;
        if ($served_iface eq $nsim_sv_name) {
            ok($served_napi > 0, "served by non-zero napi id");
            ok(abs($count - ($num_attempts/$num_threads)) <= $num_attempts * 0.10, "each queue served share of traffic");
        } elsif ( $served_iface eq "lo" ) {
            ok($served_napi == 0, "served by zero napi id");
        } else {
            ok(0, "served by unknown interface");
        }
    }
    if ($mode eq "OFF") {
        ok((get_busypoll_rx_packets() - $bprx) == 0, "zero busypoll rx packets with no busypolling");
    } else {
        ok((get_busypoll_rx_packets() - $bprx) > 0, "non-zero busypoll rx packets while busypolling");
    }

    return 0;
}
