/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* SPDX-FileCopyrightText: 2022 Kazuho Oku */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "irqbalance.h"

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, IRQBALANCE_MAX_CPUS *IRQBALANCE_MAX_SOCKS_PER_CPU);
    __type(key, __u32);
    __type(value, __u64);
} cpuid_tcp_sockmap SEC(".maps"), cpuid_udp_sockmap SEC(".maps");

SEC("sk_lookup/irqbalance")
int irqbalance(struct bpf_sk_lookup *ctx)
{
    int is_tcp;

    switch (ctx->protocol) {
    case IPPROTO_TCP:
        is_tcp = 1;
        break;
    case IPPROTO_UDP:
        is_tcp = 0;
        break;
    default:
        return SK_PASS; /* let others decide */
    }

    /* try the ones in the map in the order being provided */
    __u32 base = bpf_get_smp_processor_id() * IRQBALANCE_MAX_SOCKS_PER_CPU;
    for (__u32 offset = 0; offset < IRQBALANCE_MAX_SOCKS_PER_CPU; ++offset) {
        __u32 slot = base + offset;
        struct bpf_sock *s =
            is_tcp ? bpf_map_lookup_elem(&cpuid_tcp_sockmap, &slot) : bpf_map_lookup_elem(&cpuid_udp_sockmap, &slot);
        if (s == NULL)
             break;
        int err = bpf_sk_assign(ctx, s, BPF_SK_LOOKUP_F_NO_REUSEPORT);
        bpf_sk_release(s);
        if (err == 0)
            break;
    }

    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
