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

// max(sizeof(struct in6_addr), sizeof(struct in_addr))
#define H2O_EBPF_SIZEOF_ADDR 16
typedef struct st_h2o_ebpf_address_t {
    uint8_t ip[H2O_EBPF_SIZEOF_ADDR];
    uint16_t port;
} h2o_ebpf_address_t;

typedef struct st_h2o_ebpf_map_key_t {
    uint8_t family;
    uint8_t protocol;
    h2o_ebpf_address_t local, remote;
} h2o_ebpf_map_key_t;

/* avoid using a bit-field struct because BCC does not support it */

#define H2O_EBPF_SKIP_TRACING 0x01

// the "quic_send_retry" flag takes 3 state: default, on, off
#define H2O_EBPF_QUIC_SEND_RETRY_MASK 0x06
#define H2O_EBPF_QUIC_SEND_RETRY_ON 0x02
#define H2O_EBPF_QUIC_SEND_RETRY_OFF 0x04

#define H2O_EBPF_SKIP_TRACING_IS_SET(f) (((f)&H2O_EBPF_SKIP_TRACING) == H2O_EBPF_SKIP_TRACING)
#define H2O_EBPF_QUIC_SEND_RETRY_ON_IS_SET(f) (((f)&H2O_EBPF_QUIC_SEND_RETRY_MASK) == H2O_EBPF_QUIC_SEND_RETRY_ON)
#define H2O_EBPF_QUIC_SEND_RETRY_OFF_IS_SET(f) (((f)&H2O_EBPF_QUIC_SEND_RETRY_MASK) == H2O_EBPF_QUIC_SEND_RETRY_OFF)

// bpf_hash<h2o_ebpf_map_key_t, h2o_ebpf_map_value_t>
#define H2O_EBPF_MAP_PATH "/sys/fs/bpf/h2o_map"

// h2o_return map uses an LRU hash map (needs Linux 4.10 or later)
// bpf_lru_hash<tid_t, h2o_ebpf_map_value_t>
#define H2O_EBPF_RETURN_MAP_NAME "h2o_return"
#define H2O_EBPF_RETURN_MAP_PATH "/sys/fs/bpf/" H2O_EBPF_RETURN_MAP_NAME

// The size of pinned BPF objects, which must be larger than the number of processors.
#define H2O_EBPF_RETURN_MAP_SIZE 1024

#endif
