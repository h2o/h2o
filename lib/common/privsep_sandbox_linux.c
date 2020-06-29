/*
 * Copyright (c) 2020 Christian Peron
 *
 * This largely came from the OpenSSH seccomp filter code.
 * There are obviously changes in the syscall execution profle
 * so the policies have been updated to reflect that.
 *
 * Copyright (c) 2012 Will Drewry <wad@dataspill.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef __linux__
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#endif

#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/net.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <elf.h>

#include <asm/unistd.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>  /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "h2o/privsep.h"
#include "h2o/privsep_sandbox_linux.h"

#define H2O_SECCOMP_DEBUG 1
#ifdef H2O_SECCOMP_DEBUG
#define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#else
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL
#endif

static char *loopback_mounts[] = {
    "bin",
    "etc/alternatives",
    "etc/ssl",
    "lib",
    "lib64",
    "sbin",
    "usr/lib",
    "usr/libexec",
    "usr/bin",
    "usr/sbin",
    "usr/share",
    "usr/local",
    "proc",
    /*
     * NB: we need to re-visit this and emit commands to create a more
     * restrictive subset of the device entries.
     */
    "dev",
    NULL
};

void sandbox_emit_linux_hints(char *root)
{
    char *path, **copy;

    copy = loopback_mounts;
    /*
     * NB: copy /etc/passwd/group
     */
    /*
     * On Linux, we get away with --bind mounts to create the outer sandbox
     */
    while ((path = *copy++)) {
	printf("[ ! -d \"%s/%s\" ] && mkdir -p \"%s/%s\";\n",
	    root, path, root, path);
        printf("mount -o ro --bind /%s %s/%s;\n", path, root, path);
    }
}

static const struct sock_filter h2o_neverbleed_insns[] = {
    /*
     * Begin BPF filter program specification.
     */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, nr)),
    /*
     * Make sure signal/fault handlers work.
     */
#ifdef __NR_rt_sigaction
    SC_ALLOW(__NR_rt_sigaction),
#endif
#ifdef __NR_rt_sigreturn
    SC_ALLOW(__NR_rt_sigreturn),
#endif
#ifdef __NR_poll
    SC_ALLOW(__NR_poll),
#endif
#ifdef __NR_writev
    SC_ALLOW(__NR_writev),
#endif
#ifdef __NR_readv
    SC_ALLOW(__NR_readv),
#endif

#ifdef __NR_tgkill
    SC_ALLOW(__NR_tgkill),
#endif
#ifdef __NR_set_robust_list
    SC_ALLOW(__NR_set_robust_list),
#endif
#ifdef __NR_clone
    SC_ALLOW(__NR_clone),
#endif

#ifdef __NR_accept4
    SC_ALLOW(__NR_accept4),
#endif
#ifdef __NR_brk
    SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_clock_gettime
    SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_clock_gettime64
    SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_close
    SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit
    SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_exit_group
    SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_futex
    SC_ALLOW(__NR_futex),
#endif
#ifdef __NR_getrandom
    SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_gettimeofday
    SC_ALLOW(__NR_gettimeofday),
#endif
#ifdef __NR_getuid
    SC_ALLOW(__NR_getuid),
#endif
#ifdef __NR_getuid32
    SC_ALLOW(__NR_getuid32),
#endif
#ifdef __NR_madvise
    SC_ALLOW(__NR_madvise),
#endif
#ifdef __NR_mmap
    SC_ALLOW_ARG_MASK(__NR_mmap, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mmap2
    SC_ALLOW_ARG_MASK(__NR_mmap2, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mprotect
    SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mremap
    SC_ALLOW(__NR_mremap),
#endif
#ifdef __NR_munmap
    SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_nanosleep
    SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_clock_nanosleep
    SC_ALLOW(__NR_clock_nanosleep),
#endif
#ifdef __NR_clock_nanosleep_time64
    SC_ALLOW(__NR_clock_nanosleep_time64),
#endif
#ifdef __NR_clock_gettime64
    SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_read
    SC_ALLOW(__NR_read),
#endif
#ifdef __NR_rt_sigprocmask
    SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_shutdown
    SC_ALLOW(__NR_shutdown),
#endif
#ifdef __NR_time
    SC_ALLOW(__NR_time),
#endif
#ifdef __NR_write
    SC_ALLOW(__NR_write),
#endif
#ifdef __NR_socketcall
    SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
    SC_DENY(__NR_socketcall, EACCES),
#endif
#if defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
    /*
     * On Linux x32, the clock_gettime VDSO falls back to the
     * x86-64 syscall under some circumstances, e.g.
     * https://bugs.debian.org/849923
     */
    SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#endif
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_filter h2o_main_insns[] = {
    /*
     * Begin BPF filter program specification.
     */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, nr)),

    /*
     * Deny open(2) and openat(2) in a non-fatal manner. Often times libraries
     * open files behind the scenes but can tolerate EPERM or EACCES. This is
     * an attempt to make these operations less catstrophic while enforcing
     * sandbox boundaries.
     */
#ifdef __NR_open
    SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
    SC_DENY(__NR_openat, EACCES),
#endif
    /*
     * Make sure signal/fault handlers work.
     */
#ifdef __NR_rt_sigaction
    SC_ALLOW(__NR_rt_sigaction),
#endif
#ifdef __NR_rt_sigreturn
    SC_ALLOW(__NR_rt_sigreturn),
#endif
    /*
     * NB: required for mruby, but I think we could probably see about getting
     * a file descriptor and changing it to fstat() instead.
     */
    SC_ALLOW(__NR_lstat),
#ifdef __NR_ioctl
    SC_ALLOW(__NR_ioctl),
#endif
#ifdef __NR_sendmmsg
    SC_ALLOW(__NR_sendmmsg),
#endif
#ifdef __NR_poll
    SC_ALLOW(__NR_poll),
#endif
    /*
     * NB: stat(2) path is required by try_dynamic_request() no real way
     * around this outside of creating a priv for it. We are in a chroot
     * so this should probably be ok for now.
     */
#ifdef __NR_stat
    SC_ALLOW(__NR_stat),
#endif
#ifdef __NR_fstat
    SC_ALLOW(__NR_fstat),
#endif
#ifdef __NR_pread64
    SC_ALLOW(__NR_pread64),
#endif

#ifdef __NR_getpeername
    SC_ALLOW(__NR_getpeername),
#endif
#ifdef __NR_epoll_wait
    SC_ALLOW(__NR_epoll_wait),
#endif
#ifdef __NR_epoll_ctl
    SC_ALLOW(__NR_epoll_ctl),
#endif
#ifdef __NR_epoll_create
    SC_ALLOW(__NR_epoll_create),
#endif
#ifdef __NR_eventfd2
    SC_ALLOW(__NR_eventfd2),
#endif
#ifdef __NR_dup
    SC_ALLOW(__NR_dup),
#endif
    /*
     * I am not happy about allowing socket, but lets scope it down to allow
     * the less dangerous socket domains. i.e. smack down SOCK_SEQPACKET,
     * SOCK_RAW etc.. which requires privilge which we shouldn't have, but
     * do it anyway.
     */
#ifdef __NR_socket
    SC_ALLOW_ARG(__NR_socket, 1, SOCK_STREAM),
    SC_ALLOW_ARG(__NR_socket, 1, SOCK_DGRAM),
#endif
#ifdef __NR_socketpair
    SC_ALLOW(__NR_socketpair),
#endif
#ifdef __NR_epoll_create
    SC_ALLOW(__NR_epoll_create),
#endif
#ifdef __NR_writev
    SC_ALLOW(__NR_writev),
#endif
#ifdef __NR_readv
    SC_ALLOW(__NR_readv),
#endif

#ifdef __NR_tgkill
    SC_ALLOW(__NR_tgkill),
#endif
#ifdef __NR_set_robust_list
    SC_ALLOW(__NR_set_robust_list),
#endif
#ifdef __NR_clone
    SC_ALLOW(__NR_clone),
#endif

#ifdef __NR_accept4
    SC_ALLOW(__NR_accept4),
#endif

#ifdef __NR_pipe
    SC_ALLOW(__NR_pipe),
#endif
#ifdef __NR_getsockopt
    SC_ALLOW(__NR_getsockopt),
#endif
#ifdef __NR_setsockopt
    SC_ALLOW(__NR_setsockopt),
#endif
#ifdef __NR_sendmsg
    SC_ALLOW(__NR_sendmsg),
#endif
#ifdef __NR_recvmsg
    SC_ALLOW(__NR_recvmsg),
#endif
#ifdef __NR_sendto
    SC_ALLOW(__NR_sendto),
#endif
#ifdef __NR_recvfrom
    SC_ALLOW(__NR_recvfrom),
#endif
#ifdef __NR_sysinfo
    SC_ALLOW(__NR_sysinfo),
#endif
#ifdef __NR_fcntl
    SC_ALLOW(__NR_fcntl),
#endif
#ifdef __NR_connect
    SC_ALLOW(__NR_connect),
#endif
#ifdef __NR_accept
    SC_ALLOW(__NR_accept),
#endif
#ifdef __NR_getsockname
    SC_ALLOW(__NR_getsockname),
#endif

#ifdef __NR_brk
    SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_clock_gettime
    SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_clock_gettime64
    SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_close
    SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit
    SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_exit_group
    SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_futex
    SC_ALLOW(__NR_futex),
#endif
#ifdef __NR_geteuid
    SC_ALLOW(__NR_geteuid),
#endif
#ifdef __NR_geteuid32
    SC_ALLOW(__NR_geteuid32),
#endif
#ifdef __NR_getpgid
    SC_ALLOW(__NR_getpgid),
#endif
#ifdef __NR_getpid
    SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_getrandom
    SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_gettimeofday
    SC_ALLOW(__NR_gettimeofday),
#endif
#ifdef __NR_getuid
    SC_ALLOW(__NR_getuid),
#endif
#ifdef __NR_getuid32
    SC_ALLOW(__NR_getuid32),
#endif
#ifdef __NR_madvise
    SC_ALLOW(__NR_madvise),
#endif
#ifdef __NR_mmap
    SC_ALLOW_ARG_MASK(__NR_mmap, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mmap2
    SC_ALLOW_ARG_MASK(__NR_mmap2, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mprotect
    SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mremap
    SC_ALLOW(__NR_mremap),
#endif
#ifdef __NR_munmap
    SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_nanosleep
    SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_clock_nanosleep
    SC_ALLOW(__NR_clock_nanosleep),
#endif
#ifdef __NR_clock_nanosleep_time64
    SC_ALLOW(__NR_clock_nanosleep_time64),
#endif
#ifdef __NR_clock_gettime64
    SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_read
    SC_ALLOW(__NR_read),
#endif
#ifdef __NR_rt_sigprocmask
    SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_select
    SC_ALLOW(__NR_select),
#endif
#ifdef __NR_shutdown
    SC_ALLOW(__NR_shutdown),
#endif
#ifdef __NR_time
    SC_ALLOW(__NR_time),
#endif
#ifdef __NR_write
    SC_ALLOW(__NR_write),
#endif
#ifdef __NR_socketcall
    SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
    SC_DENY(__NR_socketcall, EACCES),
#endif
#if defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
    /*
     * On Linux x32, the clock_gettime VDSO falls back to the
     * x86-64 syscall under some circumstances, e.g.
     * https://bugs.debian.org/849923
     */
    SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#endif

    /* Default deny */
    //BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (SECCOMP_RET_DATA & EACCES)),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog h2o_main_program = {
    .len = (sizeof(h2o_main_insns)/sizeof(h2o_main_insns[0])),
    .filter = (struct sock_filter *)h2o_main_insns,
};


static const struct sock_fprog h2o_neverbleed_program = {
    .len = (sizeof(h2o_neverbleed_insns)/sizeof(h2o_neverbleed_insns[0])),
    .filter = (struct sock_filter *)h2o_neverbleed_insns,
};

static void
sandbox_violation(int signum, siginfo_t *info, void *void_context)
{
    char msg[256];

    snprintf(msg, sizeof(msg),
        "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
        __func__, info->si_arch, info->si_syscall, info->si_call_addr);
    printf("%s\n", msg);
    fflush(stdout);
    _exit(1);
}

static void
sandbox_child_debugging(void)
{
    struct sigaction act;
    sigset_t mask;

    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);
    act.sa_sigaction = &sandbox_violation;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &act, NULL) == -1) {
        fprintf(stderr, "%s: sigaction(SIGSYS): %s\n", __func__, strerror(errno));
        exit(1);
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
        fprintf(stderr, "%s: sigprocmask(SIGSYS): %s", __func__, strerror(errno));
        exit(1);
    }
}

void
sandbox_bind_linux(int policy)
{
    const struct sock_fprog *fprog;
    char *ptype;

    ptype = NULL;
    fprog = NULL;
    sandbox_child_debugging();
    switch (policy) {
    case SANDBOX_POLICY_NEVERBLEED:
        ptype = "neverbleed";
        fprog = &h2o_neverbleed_program;
        break;
    case SANDBOX_POLICY_H2OMAIN:
        ptype = "h2o_main";
        fprog = &h2o_main_program;
        break;
    default:
        abort();
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        printf("%s: prctl(PR_SET_NO_NEW_PRIVS): %s", __func__, strerror(errno));
        exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog) == -1) {
        printf("%s: prctl(PR_SET_SECCOMP): %s", __func__, strerror(errno));
        exit(1);
    }
    printf("[PRIVSEP] sandbox type: SECCOMP-BPF bound. policy: %s\n", ptype);
}
#endif	/* __linux__ */
