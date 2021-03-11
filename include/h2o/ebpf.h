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

// This file may be included in a BPF program

// sizeof(struct in6_addr)
#define H2O_EBPF_SIZEOF_ADDR 16
typedef struct st_h2o_ebpf_address_t {
    uint8_t ip[H2O_EBPF_SIZEOF_ADDR];
    uint16_t port;
} h2o_ebpf_address_t;

typedef struct st_h2o_ebpf_map_key_t {
    /**
     * SOCK_STZREAM or SOCK_DGRAM
     */
    int sock_type;

    /**
     * AF_INET or AF_INET6
     */
    int sa_family;
    /**
     * The local, destination adddress in sockaddr_in or sockaddr_in6.
     */
    h2o_ebpf_address_t local;
    /**
     * The remote, source address in sockaddr_in or sockaddr_in6.
     */
    h2o_ebpf_address_t remote;
} h2o_ebpf_map_key_t;

#define H2O_EBPF_QUIC_SEND_RETRY_DEFAULT 0
#define H2O_EBPF_QUIC_SEND_RETRY_ON 1
#define H2O_EBPF_QUIC_SEND_RETRY_OFF 2

typedef struct st_h2o_ebpf_map_value_t {
    uint64_t skip_tracing : 1;
    uint64_t quic_send_retry : 2;
} h2o_ebpf_map_value_t;

// bpf_hash<h2o_ebpf_map_key_t, h2o_ebpf_map_value_t>
#define H2O_EBPF_MAP_PATH "/sys/fs/bpf/h2o_map"

// bpf_hash<tid_t, uint64_t>
#define H2O_EBPF_TID2U64_MAP_PATH "/sys/fs/bpf/h2o_tid_to_u64"

#endif
