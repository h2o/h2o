/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* SPDX-FileCopyrightText: 2022 Kazuho Oku */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "irqbalance.h"

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, IRQBALANCE_MAX_CPUS);
    __type(key, __u32);
    __type(value, __u64);
} sockarray SEC(".maps");

SEC("sk_reuseport")
int irqbalance(struct sk_reuseport_md *md)
{
    __u32 slot = bpf_get_smp_processor_id();
    bpf_sk_select_reuseport(md, &sockarray, &slot, 0);

    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
