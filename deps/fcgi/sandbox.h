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
#ifndef SANDBOX_LINUX_DOT_H_
#define SANDBOX_LINUX_DOT_H_

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  sizeof(uint32_t)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  sizeof(uint32_t)
# define ARG_HI_OFFSET  0
#else
#error "Unknown endianness"
#endif

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
    /* load and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        ((_arg_val) & 0xFFFFFFFF), 0, 3), \
    /* load and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))

#define SC_DENY_ARG_MASK(_nr, _arg_nr, _arg_mask) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
    /* load, mask and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
    /* load, mask and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
        ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))

/*
 BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)),
 BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
 */
/* Allow if syscall argument contains only values in mask */
#define SC_ALLOW_ARG_MASK(_nr, _arg_nr, _arg_mask) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
    /* load, mask and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
    /* load, mask and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
        ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))

void        sandbox_bind(int);
void        sandbox_exec(struct wait_params *, char **, char **);

#endif  /* SANDBOX_LINUX_DOT_H_ */
