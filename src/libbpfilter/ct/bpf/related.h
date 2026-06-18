/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>

#include "cgen/runtime.h"
#include "ct/bpf/helpers.h"
#include "ct/bpf/key.h"
#include "ct/bpf/maps.h"
#include "ct/bpf/parse.h"
#include "ct/bpf/stats.h"

static __always_inline __u8
bf_ct_bpf_lookup_related_v4(const struct bf_runtime *ctx,
                            const struct icmphdr *icmp)
{
    const struct iphdr *inner_ip;
    struct ct_key_v4 inner_key = {};
    struct ct_entry *entry;
    void *flow_map;
    const void *l4;
    __u32 inner_off;
    __u8 inner_transport[8];
    __u32 inner_ihl;
    __u32 sport = 0;
    __u32 dport = 0;
    __u8 orig_lo_is_src;

    l4 = bf_ct_bpf_l4(ctx);
    if (!l4 || ctx->l4_size < sizeof(*icmp) + sizeof(struct iphdr))
        return CT_STATE_INVALID;

    inner_off = sizeof(*icmp);
    inner_ip = (const struct iphdr *)(l4 + inner_off);

    inner_ihl = ((__u32)inner_ip->ihl) * 4;
    if (inner_ihl < 20 || inner_ihl > 60)
        return CT_STATE_INVALID;

    if (ctx->l4_size < inner_off + inner_ihl + 8)
        return CT_STATE_INVALID;

    __builtin_memcpy(inner_transport, l4 + inner_off + inner_ihl, 8);

    switch (inner_ip->protocol) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
        sport = bpf_ntohs(*(__u16 *)&inner_transport[0]);
        dport = bpf_ntohs(*(__u16 *)&inner_transport[2]);
        break;
    default:
        break;
    }

    bf_ct_bpf_key_normalize_v4(inner_ip->saddr, inner_ip->daddr, sport, dport,
                               inner_ip->protocol, &inner_key, &orig_lo_is_src);

    flow_map = (inner_key.proto == IPPROTO_TCP) ? (void *)&bf_ct_map_tcp :
                                                  (void *)&bf_ct_map_any;
    entry = bpf_map_lookup_elem(flow_map, &inner_key);
    if (!entry)
        return CT_STATE_INVALID;

    entry->last_seen_ns = bpf_ktime_get_ns();
    bf_ct_bpf_stats_related((void *)&bf_ct_map_stats);
    return CT_STATE_RELATED;
}

static __always_inline __u8
bf_ct_bpf_lookup_related_v6(const struct bf_runtime *ctx,
                            const struct icmp6hdr *icmp6)
{
    const struct ipv6hdr *inner_ip;
    struct ct_key_v6 inner_key = {};
    struct ct_entry *entry;
    void *flow_map;
    const void *l4;
    __u32 inner_off;
    __u8 inner_transport[8];
    __u32 sport = 0;
    __u32 dport = 0;
    __u8 orig_lo_is_src;

    l4 = bf_ct_bpf_l4(ctx);
    if (!l4 || ctx->l4_size < sizeof(*icmp6) + sizeof(struct ipv6hdr) + 8)
        return CT_STATE_INVALID;

    inner_off = sizeof(*icmp6);
    inner_ip = (const struct ipv6hdr *)(l4 + inner_off);

    __builtin_memcpy(inner_transport, l4 + inner_off + sizeof(*inner_ip), 8);

    switch (inner_ip->nexthdr) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
        sport = bpf_ntohs(*(__u16 *)&inner_transport[0]);
        dport = bpf_ntohs(*(__u16 *)&inner_transport[2]);
        break;
    default:
        break;
    }

    bf_ct_bpf_key_normalize_v6(&inner_ip->saddr, &inner_ip->daddr, sport,
                               dport, inner_ip->nexthdr, &inner_key,
                               &orig_lo_is_src);

    flow_map = (inner_key.proto == IPPROTO_TCP) ? (void *)&bf_ct_map_tcp6 :
                                                  (void *)&bf_ct_map_any6;
    entry = bpf_map_lookup_elem(flow_map, &inner_key);
    if (!entry)
        return CT_STATE_INVALID;

    entry->last_seen_ns = bpf_ktime_get_ns();
    bf_ct_bpf_stats_related((void *)&bf_ct_map_stats);
    return CT_STATE_RELATED;
}

static __always_inline __u8
bf_ct_bpf_lookup_related(const struct bf_runtime *ctx,
                         const struct bf_ct_pkt_info *pkt)
{
#ifdef BF_CT_BPF_HARNESS
    if (!pkt->is_v6 && pkt->proto == IPPROTO_ICMP && pkt->icmp)
        return bf_ct_bpf_lookup_related_v4(ctx, pkt->icmp);
    if (pkt->is_v6 && pkt->proto == IPPROTO_ICMPV6 && pkt->icmp6)
        return bf_ct_bpf_lookup_related_v6(ctx, pkt->icmp6);
    return CT_STATE_INVALID;
#else
    /* ICMP-error "related" tracking is disabled in the real datapath. It must
     * read the original packet embedded in the ICMP payload (an inner IP
     * header plus transport ports, up to ~76 bytes into L4), which exceeds the
     * embedded L4 copy. Reading it with bpf_dynptr_read() from the CT
     * subprogram is not possible: the dynptr lives in the caller frame, and
     * passing a pointer to it makes the verifier scalarize the spilled CT map
     * pointers, breaking the subsequent map lookups.
     *
     * @todo Re-enable by pre-staging a larger L4 region (~80 bytes) into a
     *       dedicated runtime buffer in the program prologue (where the dynptr
     *       is available and the maps are not yet spilled), then read the
     *       inner packet from that buffer here. */
    (void)ctx;
    (void)pkt;
    return CT_STATE_INVALID;
#endif
}
