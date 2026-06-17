/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include "ct/bpf/helpers.h"

static __always_inline void bf_ct_bpf_stats_established(void *stats_map)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (stats)
        stats->established++;
}

static __always_inline void bf_ct_bpf_stats_related(void *stats_map)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (stats)
        stats->related++;
}

static __always_inline void bf_ct_bpf_stats_invalid(void *stats_map)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (stats)
        stats->invalid++;
}

static __always_inline void bf_ct_bpf_stats_rate_drop(void *stats_map)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (stats)
        stats->dropped_rate_limit++;
}

static __always_inline void bf_ct_bpf_stats_count_drop(void *stats_map)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (stats)
        stats->dropped_src_count++;
}

static __always_inline void bf_ct_bpf_stats_new(void *stats_map, __u8 proto)
{
    struct ct_stats_counters *stats;
    __u32 key = 0;

    stats = bpf_map_lookup_elem(stats_map, &key);
    if (!stats)
        return;

    switch (proto) {
    case IPPROTO_TCP:
        stats->new_tcp++;
        break;
    case IPPROTO_UDP:
        stats->new_udp++;
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        stats->new_icmp++;
        break;
    default:
        stats->new_other++;
        break;
    }
}
