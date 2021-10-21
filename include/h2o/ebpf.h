/*
 * Copyright (c) 2019 Fastly Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef h2o__ebpf_h
#define h2o__ebpf_h

/*
 * This file may be included by a BPF program. A BPF program written in C can include a few system headers, for example
 * linux/sched.h and inttypes.h. However, most of the standard C/POSIX headers, for example stdio.h and socket.h, are unavailable.
 * ebpf.h MUST only depend on the include files available to the BPF compiler.
 */

typedef struct st_h2o_ebpf_address_t {
    uint8_t ip[16];
    uint16_t port;
} h2o_ebpf_address_t;

typedef struct st_h2o_ebpf_map_key_t {
    uint8_t family;
    uint8_t protocol;
    h2o_ebpf_address_t local, remote;
} h2o_ebpf_map_key_t;

/**
 * `H2O_EBPF_FLAGS_*` are the value type of the pinned BPF maps: h2o_map and h2o_return
 */
#define H2O_EBPF_FLAGS_SKIP_TRACING_BIT 0x01

/**
 * QUIC_SEND_RETRY bits take 2 bits for 3 state: default, on, off
 */
#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_MASK 0x06
#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_BITS_ON 0x02
#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_BITS_OFF 0x04

/**
 * A pinned BPF map to control connection flags.
 * The key type is h2o_ebpf_map_key_t, and the value type is uint64_t that contains `H2O_EBPF_FLAGS_*`.
 */
#define H2O_EBPF_MAP_PATH "/sys/fs/bpf/h2o_map"

/**
 * A pinned BPF map to control connection flags, used together with h2o:socket_lookup_flags probe.
 * The key type is a thread ID typed as pid_t obtained by `gettid()`, and the value type is uint64_t that contains
 * `H2O_EBPF_FLAGS_*`.
 * See also h2o-probes.d.
 */
#define H2O_EBPF_RETURN_MAP_NAME "h2o_return"
#define H2O_EBPF_RETURN_MAP_PATH "/sys/fs/bpf/" H2O_EBPF_RETURN_MAP_NAME

/**
 * The size of pinned BPF objects.
 * The size must be much larger than the number of worker threads and the safe value seems to depend on the system,
 */
#define H2O_EBPF_RETURN_MAP_SIZE 1024

#endif
