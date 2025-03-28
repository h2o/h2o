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

ok(prog_exists("ethtool"), "have ethtool");
ok(prog_exists("udevadm"), "have udevadm");

my $nsim_sv_id = 256 + int(rand(256));
my $nsim_cl_id = 512 + int(rand(256));
my $nsim_sv_fd;
my $nsim_cl_fd;
my $nsim_sv_ifidx;
my $nsim_cl_ifidx;
my $nsim_sv_name;
my $nsim_cl_name;

my $nsim_sv_sys = "/sys/bus/netdevsim/devices/netdevsim$nsim_sv_id";
my $nsim_cl_sys = "/sys/bus/netdevsim/devices/netdevsim$nsim_cl_id";
my $nsim_dev_sys_new = "/sys/bus/netdevsim/new_device";
my $nsim_dev_sys_del = "/sys/bus/netdevsim/del_device";
my $nsim_dev_sys_link = "/sys/bus/netdevsim/link_device";
my $nsim_dev_sys_unlink = "/sys/bus/netdevsim/unlink_device";

my $server_ip = "192.168.1.1";
my $client_ip = "192.168.1.2";

# busy poll config
my $busy_poll_usecs = 0;
my $busy_poll_budget = 16;

# IRQ deferral config
my $napi_defer_hard_irqs = 100;
my $gro_flush_timeout = 50000;
my $suspend_timeout = 20000000;

subtest "busypoller" => sub {
    cleanup_ns();
    create_devices();
    setup_ns();
    link_devices();
    ok(test_busypoll() == 0, "busypoll test succeeded");
    ok(test_busypoll($suspend_timeout) == 0, "busypoll with suspend test succeeded");
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
    ok(system("echo $nsim_sv_id > $nsim_dev_sys_new") == 0, "new server device");
    ok(system("echo $nsim_cl_id > $nsim_dev_sys_new") == 0, "new client device");
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

    ok(system("ethtool -L $nsim_sv_name combined 1") == 0, "Ensure server has 1 queue");

    ok(system("ip link set $nsim_sv_name netns nssv") == 0, "server iface moved to server ns");
    ok(system("ip link set $nsim_cl_name netns nscl") == 0, "client iface moved to client ns");

    ok(system("ip netns exec nssv ip addr add \"$server_ip/24\" dev $nsim_sv_name") == 0, "server ip assigned");
    ok(system("ip netns exec nscl ip addr add \"$client_ip/24\" dev $nsim_cl_name") == 0, "client ip assigned");

    ok(system("ip netns exec nssv ip link set dev $nsim_sv_name up") == 0, "server iface up");
    ok(system("ip netns exec nscl ip link set dev $nsim_cl_name up") == 0, "client iface up");
}

sub cleanup_ns {
    system("ip netns del nscl 2>/dev/null");
	system("ip netns del nssv 2>/dev/null");
}

sub test_busypoll {
    my $suspend_value = shift // 0;
    my $busypoll_mode = ($suspend_value > 0) ? 'BUSYPOLL' : 'SUSPEND';

    my ($port) = empty_ports(1, { host => "0.0.0.0" });

    # why does h2o fail to start with spawn_h2o_raw(<< "EOT", [$port], [], "nssv"); ??

    my $h2o_sv = spawn_h2o_raw(<< "EOT", [], [], "nssv");
listen:
  host: $server_ip
  port: $port
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
    access-log:
      path: /dev/stdout
      format: "%h %t %s %b %{bp.iface}x %{bp.napi-id}x %{bp.cpu-idx}x"

capabilities:
  - CAP_NET_ADMIN
tcp-reuseport: ON
num-threads: 1

epoll-nonblock: ON
busy-poll-budget: $busy_poll_budget
busy-poll-usecs: $busy_poll_usecs

busy-poll-map:
  interfaces:
    - ifindex: $nsim_sv_ifidx
      cpus:
        - 1
      options:
        gro-flush-timeout: $gro_flush_timeout
        defer-hard-irqs: $napi_defer_hard_irqs
        suspend-timeout: $suspend_value
        mode: $busypoll_mode

EOT

    my $ss_out = `ip netns exec nssv ss -tlnp`;
    diag("LISTENERS:\n" . $ss_out);

    my $resp = `ip netns exec nscl curl -kssi http://$server_ip:$port`;
    like $resp, qr{^HTTP/1.1 200 OK\r\n}s, "curl request ok";

    return 0;
}
