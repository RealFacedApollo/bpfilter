/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include "ct/bpf/helpers.h"
#include "ct/bpf/key.h"

static __always_inline __u32 bf_ct_bpf_rate_limit(__u8 proto)
{
    switch (proto) {
    case IPPROTO_TCP:
        return CT_RATE_LIMIT_TCP;
    case IPPROTO_UDP:
        return CT_RATE_LIMIT_UDP;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return CT_RATE_LIMIT_ICMP;
    default:
        return CT_RATE_LIMIT_OTHER;
    }
}

static __always_inline __u32 bf_ct_bpf_src_count_limit(__u8 proto)
{
    switch (proto) {
    case IPPROTO_TCP:
        return CT_MAX_ENTRIES_PER_SRC_TCP;
    case IPPROTO_UDP:
        return CT_MAX_ENTRIES_PER_SRC_UDP;
    default:
        return CT_MAX_ENTRIES_PER_SRC_OTHER;
    }
}

static __always_inline int bf_ct_bpf_rate_check(void *src_rate_map,
                                                const struct ct_ip_key *key,
                                                __u8 proto, __u64 now_ns)
{
    struct ct_rate_entry *entry;
    __u32 limit = bf_ct_bpf_rate_limit(proto);

    entry = bpf_map_lookup_elem(src_rate_map, key);
    if (!entry) {
        struct ct_rate_entry fresh = {
            .window_start_ns = now_ns,
            .pkt_count = 1,
        };

        bpf_map_update_elem(src_rate_map, key, &fresh, BPF_ANY);
        return 0;
    }

    if (now_ns - entry->window_start_ns >= CT_RATE_WINDOW_NS) {
        entry->window_start_ns = now_ns;
        entry->pkt_count = 1;
        return 0;
    }

    if (entry->pkt_count >= limit)
        return 1;

    entry->pkt_count += 1;
    return 0;
}

static __always_inline int
bf_ct_bpf_src_count_check(void *src_count_map, const struct ct_ip_key *key,
                          __u8 proto)
{
    struct ct_src_count_entry *entry;
    __u32 limit = bf_ct_bpf_src_count_limit(proto);

    entry = bpf_map_lookup_elem(src_count_map, key);
    if (!entry)
        return 0;

    return entry->count >= limit;
}

static __always_inline void
bf_ct_bpf_src_count_inc(void *src_count_map, const struct ct_ip_key *key)
{
    struct ct_src_count_entry *entry;
    struct ct_src_count_entry fresh = {
        .count = 1,
    };

    entry = bpf_map_lookup_elem(src_count_map, key);
    if (!entry) {
        bpf_map_update_elem(src_count_map, key, &fresh, BPF_ANY);
        return;
    }

    entry->count += 1;
}
