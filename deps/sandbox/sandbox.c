/* Use the kernel headers in case of an older toolchain. */
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1

#include <execinfo.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>

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

#include "sandbox.h"

/* Syscall filtering set for preauth. */
static const struct sock_filter ins[] = {
    /* Ensure the syscall arch convention is as expected. */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
    /* Load the syscall number for checking. */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, nr)),
    /*
     * Start of our syscall policy. Typically we do not want anything that can
     * manipulate any of the global namespace(s). This includes open files, sockets
     * system V IPC primitives to name a few. Some of these will require additional
     * scoping (i.e.: the use of SC_ALLOW_ARG() macro to check for specific arguments.
     */
    SC_ALLOW(__NR_epoll_ctl),
    SC_ALLOW(__NR_epoll_wait),
    /*
     * Allow accept(2) and accept4(2) since it doesn't manipulate any global namespaces
     * rather relies on existing socket bindings.
     */
    SC_ALLOW(__NR_accept),
    SC_ALLOW(__NR_accept4),
    /*
     * Allow writev(2) since it doesn't manipulate any global namespaces
     */
    SC_ALLOW(__NR_writev),
    /*
     * Allow the querying of trivial global state
     */
    SC_ALLOW(__NR_getpeername),
    /*
     * We will revisit some of these more dangerous syscalls.
     */
    SC_ALLOW(__NR_mprotect), /* NB */
    SC_ALLOW(__NR_access), /* We definately need to create privileged operations for these */
    SC_ALLOW(__NR_open),
    /*
     * Allow basic IO functions to occur, again these assume there is a file
     * descriptor already created.
     */
    SC_ALLOW(__NR_lseek),
    SC_ALLOW(__NR_fstat),
    SC_ALLOW(__NR_pread64),
    SC_ALLOW(__NR_getsockopt),
    SC_ALLOW(__NR_setsockopt),  /* NB: This might be dangerous, we should probably be inspecting args */
    SC_ALLOW(__NR_recvmsg),
    /*
     * Standard syscalls required to do pretty much anything. similar to seccomp(SECCOMP_SET_MODE_STRICT)
     */
    SC_ALLOW(__NR_close),
    SC_ALLOW(__NR_write),
    SC_ALLOW(__NR_read),
    SC_ALLOW(__NR_exit),
    /*
     * Allow h2o to manipulate data segments in the process
     */
    SC_ALLOW(__NR_brk),
    SC_ALLOW(__NR_mmap),
    /*
     * h2o is threaded, so we will need futex(2)
     */
    SC_ALLOW(__NR_futex),
    /*
     * Deny the execution of all other syscalls.
     */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(ins) / sizeof(ins[0])),
    .filter = (struct sock_filter *)ins,
};

static void sandbox_backtrace(void)
{
#define NPTRS 1024
    void *frame_ptrs[NPTRS];
    char **symbols;
    int k, nptrs;

    fprintf(stderr, "-- backtrace --\n");
    nptrs = backtrace(frame_ptrs, NPTRS);
    fprintf(stderr, "backtrace: processed %d addresses\n", nptrs);
    symbols = backtrace_symbols(frame_ptrs, nptrs);
    if (symbols == NULL) {
        return;
    }
    for (k = 0; k < nptrs; k++) {
        fprintf(stderr, "-- %s\n", symbols[k]);
    }
    free(symbols);
}

void sandbox_violation(int signum, siginfo_t *info, void *void_context)
{
    char msg[256];

    snprintf(msg, sizeof(msg),
        "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
        __func__, info->si_arch, info->si_syscall, info->si_call_addr);
    fprintf(stderr, "[seccomp] %s\n", msg);
    raise(SIGQUIT);
    sandbox_backtrace();
    _exit(1);
}

static void sandbox_child_debugging(void)
{
    struct sigaction act;
    sigset_t mask;

    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    act.sa_sigaction = &sandbox_violation;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &act, NULL) == -1)
        fprintf(stderr, "%s: sigaction(SIGSYS): %s", __func__, strerror(errno));
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        fprintf(stderr, "%s: sigprocmask(SIGSYS): %s",
              __func__, strerror(errno));
}

void sandbox_set(void)
{

    sandbox_child_debugging();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        fprintf(stderr, "%s: prctl(PR_SET_NO_NEW_PRIVS): %s",
              __func__, strerror(errno));
        abort();
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        fprintf(stderr, "%s: prctl(PR_SET_SECCOMP): %s",
              __func__, strerror(errno));
        abort();
    }
}

/*
 * This  is a noop right now, but we will use this to initialize function
 * pointers for the various sandboxing technologies on other operating
 * systems when supported.
 */
void sandbox_init(void)
{

    return;
}
