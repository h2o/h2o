/*
 * Copyright (c) 2020 Christian S.J. Peron
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

#include <sysexits.h>
#include <errno.h>
#include <assert.h>
#include <err.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>  /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libgen.h>

#include "fcgi.h"
#include "sandbox.h"

#define H2O_SECCOMP_DEBUG 1
#ifdef H2O_SECCOMP_DEBUG
#define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#else
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL
#endif

static const struct sock_filter basic_deny_insns[] = {
    /* 
     * Begin BPF filter program specification.
     */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, nr)),
#ifdef _NR_execveat
    SC_ALLOW(__execveat),
#endif
#ifdef __NR_execve
    SC_DENY(__NR_execve, EACCES),
#endif
#ifdef __NR_socketcall
    SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
    SC_DENY(__NR_socketcall, EACCES),
#endif
#ifdef __NR_socket
    SC_DENY(__NR_socket, EACCES),
#endif
#ifdef __NR_ptrace
    SC_DENY(__NR_ptrace, EACCES),
#endif
#ifdef __NR_kexec_load
    SC_DENY(__NR_kexec_load, EACCES),
#endif
#ifdef __NR_exec_file_load
    SC_DENY(__NR_exec_file_load, EACCES),
#endif
#ifdef __NR_shmget
    SC_DENY(__NR_shmget, EACCES),
#endif
#ifdef __NR_shmat
    SC_DENY(__NR_shmat, EACCES),
#endif
#ifdef __NR_shmctl
    SC_DENY(__NR_shmctl, EACCES),
#endif
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
};  

static const struct sock_fprog h2o_basic_program = {
    .len = (sizeof(basic_deny_insns) / sizeof(basic_deny_insns[0])),
    .filter = (struct sock_filter *)basic_deny_insns,
};

static int disect_path(char *orig, char **dir, char **base)
{
    char *dir_copy, *base_copy;

    dir_copy = strdup(orig);
    if (dir_copy == NULL) {
        return (-1);
    }
    (void) dirname(dir_copy);
    *dir = dir_copy;
    if (*dir == NULL) {
        return (-1);
    }
    base_copy = strdup(orig);
    if (base_copy == NULL) {
        free(dir_copy);
        return (-1);
    }
    (void) basename(base_copy);
    *base = base_copy;
    if (*base == NULL) {
        free(dir_copy);
        free(base_copy);
        return (-1);
    }
    return (0);
}

void sandbox_bind(int flags)
{
    const struct sock_fprog *fprog;

    fprog = &h2o_basic_program;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        err(1, "prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog) == -1) {
        err(1, "prctl(PR_SET_SECCOMP)");
    }
    printf("[SANDBOX] fastcgi: type: Linux SECCOMP-BPF bound to process\n");
}

void sandbox_exec(struct wait_params *wp, char **argv, char **env)
{
    char *base, *dir;
    int fd;

    base = NULL;
    fd = -1;
    if (wp->do_sandbox) {
        if (disect_path(*argv, &dir, &base)) {
            errx(EX_OSERR, "failed to process supplied path");
        }
        fd = open(dir, O_RDONLY | O_DIRECTORY);
        if (fd == -1) {
            free(base);
            free(dir);
            err(1, "open('%s') failed", dir);
        }
        free(dir);
    }
    sandbox_bind(0);
    switch (wp->do_sandbox) {
    case 0:
        execve(*argv, argv, env);
        break;
    default:
        assert(base != NULL && fd >= 0);
        syscall(__NR_execveat, fd, base, argv, env, 0);
        break;
    }
    if (wp->do_sandbox) {
        free(base);
    }
    err(EX_OSERR, "execveat failed: sandbox=%d", wp->do_sandbox);
}
#endif  /* __linux__ */
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/capsicum.h>

#include <stdio.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sysexits.h>

#include "fcgi.h"
#include "sandbox.h"

/*
 * Standard directories for runtime shared objects. We should probably make
 * this tunable so the users can specify alternative paths if they want.
 *
 * NOTE: These paths must be relative to the sandbox root.
 */
static char *static_lib_dirs[] = {
    "lib",
    "usr/lib",
    "usr/local/lib",
    NULL
};

/*
 * Construct the argv vector that will be used to execute the ELF laoder
 * with the FastCGI handler + args.
 */
static char **rtld_argv(char **argv, int binfd)
{
    char **ret, **copy, *f, *p, namebuf[128];
    size_t nalloc;
    int counter;

    assert(argv != NULL);
    counter = 0;
    copy = argv;
    while ((p = *copy++)) {
        counter++;
    }
    /*
     * Allocate pointers for the number of fields in the original vector plus
     * the 4 (described above), plus 1 for the terminating NULL pointer.
     */
    nalloc = counter + 4 + 1;
    ret = calloc(nalloc, sizeof(p));
    if (ret == NULL) {
        err(1, "sandbox: failed to allocate memory");
    }
    (void) snprintf(namebuf, sizeof(namebuf), "[fcgi-sandbox] %s", *argv);
    counter = 0;
    p = strdup(namebuf);
    if (p == NULL) {
        err(1, "sandbox: failed to allocate memory");
    }
    ret[counter++] = p;
    ret[counter++] = "-f";
    (void) snprintf(namebuf, sizeof(namebuf), "%d", binfd);
    p = strdup(namebuf);
    if (p == NULL) {
        err(1, "sandbox: failed to allocate memory");
    }
    ret[counter++] = p;
    ret[counter++] = "--";
    copy = argv;
    while ((f = *copy++)) {
        ret[counter++] = f;
    }
    ret[counter] = NULL;
    return (ret);
}

/*
 * Loop through a list containing all the standard lib directories relative
 * to the sandbox root and obtain file descriptors for these directories.
 * These file descriptors will be used by the runtime linker to load any
 * runtime libraries. This is required because in capability mode, the
 * linker will not have traditional access to the file system namespace.
 */
static char *emit_library_path_fds(void)
{
    char **lib_dirs, *dir, fdbuf[8], ret[1024], *ptr;
    size_t total, count;
    int fd;

    count = 0;
    total = sizeof(static_lib_dirs) / sizeof(static_lib_dirs[0]);
    lib_dirs = static_lib_dirs;
    bzero(ret, sizeof(ret));
    while ((dir = *lib_dirs++)) {
        count++;
        fd = openat(AT_FDCWD, dir, O_DIRECTORY | O_RDONLY);
        if (fd == -1) {
            err(1, "sandbox: openat(%s) failed", dir);
        }
        snprintf(fdbuf, sizeof(fdbuf), "%d", fd);
        strcat(ret, fdbuf);
        if (count < total) {
            strcat(ret, ":");
        }
    }
    ptr = strdup(ret);
    if (ptr == NULL) {
        err(1, "sandbox: failed to alloc memory");
    }
    return (ptr);
}

/*
 * Execute the FastCGI handler in the context of a Capsicum sandbox.
 */
void sandbox_exec(struct wait_params *wp, char **argv, char **env)
{
    char *lib_path_fds, **rtld_vec, fdbuf[8];
    int rtld_fd, bin_fd, root_fd;
    extern char **environ;

    if (wp->do_sandbox == 0) {
        execve(*argv, argv, env);
        err(1, "execve(%s) failed: sandbox disabled", *argv);
    }
    /*
     * We are in the chrooted sandbox, move to the root of the
     * outer sandbox because our openat(2) operations will be
     * relative to the root of the sandbox.
     *
     * In capability mode, we need to execute ELF using the
     * ELF interpreter directly (rtld-elf). Open a file descritor
     * to the interpreter first.
     */
    if (chdir("/") == -1) {
        err(1, "sandbox: failed to chdir to sandbox root");
    }
    rtld_fd = openat(AT_FDCWD, "/libexec/ld-elf.so.1", O_RDONLY);
    if (rtld_fd == -1) {
        err(1, "sandbox: failed to open the ELF runtime linker");
    }
    /*
     * In capability (sandbox) mode, we do not have access to the global
     * file system namespace. If our executable is dynamically linked the
     * runtime linker will need to know where to find the shared objects.
     *
     * Open a bunch of file descriptors for standard libraries containing
     * the shared objects and stuff them into the LD_LIBRARY_PATH_FDS
     * environment variable. The runtime linker will use these file descriptors
     * to mmap(2) in the code instead of the pathnames.
     */
    lib_path_fds = emit_library_path_fds();
    assert(lib_path_fds != NULL);
    if (setenv("LD_LIBRARY_PATH_FDS", lib_path_fds, 1) != 0) {
        err(1, "setenv(LD_LIBRARY_PATH_FDS) failed");
    }
    /*
     * We want to faciliate some basic operations within the sandbox. We will
     * set an environment variable telling the wrapper library where the
     * sandbox file descriptor is.
     *
     * We will also specify the libc wrapper to preload. Otherwise fastcgi
     * handlers that do not know they are running in a sandbox will attempt
     * to access the global file system namespace, and this will not work
     * when the process is in capability mode.
     */
    if (wp->libc_wrapper) {
        root_fd = openat(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY);
        if (root_fd == -1) {
            err(1, "openat(root fd) failed");
        }
        (void) snprintf(fdbuf, sizeof(fdbuf), "%d", root_fd);
        if (setenv("H2O_SANDBOX_ROOT_FD", fdbuf, 1) != 0) {
            err(1, "setenv(H2O_SANDBOX_ROOT_FD) failed");
        }
        if (setenv("LD_PRELOAD", wp->libc_wrapper, 1) != 0) {
            err(1, "setenv(LD_PRELOAD) failed");
        }
    }
    /*
     * Now we need to get a file descriptor for the FastCGI handler itself.
     * For example (/usr/local/bin/php-cgi). This process will be handling
     * request data containing potentially malicious payloads.
     *
     * We will convert it to a string so we can pass it on the "command line"
     * of the runtime when we activate the executable.
     */
    bin_fd = openat(AT_FDCWD, *argv, O_RDONLY);
    if (bin_fd == -1) {
        err(1, "openat(%s) failed", *argv);
    }
    rtld_vec = rtld_argv(argv, bin_fd);
    sandbox_bind(0);
    fexecve(rtld_fd, rtld_vec, environ);
    err(EX_OSERR, "fexecve failed: sandbox enabled");
}

void sandbox_bind(int flags)
{

    if (cap_enter() == -1) {
        err(1, "cap_enter() failed");
    }
    printf("[SANDBOX] fastcgi: type: FreeBSD CAPSICUM bound to process\n");
}
#endif  /* __FreeBSD */
