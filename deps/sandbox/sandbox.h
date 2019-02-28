/*
 * Copyright (c) 2019 Christian S.J. Peron
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
#ifndef SANDBOX_DOT_H_
#define SANDBOX_DOT_H_

#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL
#define SANDBOX_SECCOMP_FILTER_DEBUG 1

/* Use a signal handler to emit violations when debugging */
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

#if defined(__i386__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#  ifndef EM_ARM
#    define EM_ARM 40
#  endif
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__mips__)
#  if defined(__MIPSEL__)
#    if defined(__LP64__)
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL64
#    else
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#    endif
#  elif defined(__LP64__)
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS64
#  else
#    define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS
#  endif
#else
#  error "Platform does not support seccomp filter yet"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  sizeof(uint32_t)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  sizeof(uint32_t)
# define ARG_HI_OFFSET  0
#else
#error "Unknown endianness"
#endif

/* Simple helpers to avoid manual errors (but larger BPF programs). 
 * From openssh:
 * Copyright (c) 2012 Will Drewry <wad@dataspill.org>
 */
#define SC_DENY(_nr, _errno) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
    /* load and test first syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        ((_arg_val) & 0xFFFFFFFF), 0, 3), \
    /* load and test first syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))

void    sandbox_init(void);
void    sandbox_set(void);

#endif
