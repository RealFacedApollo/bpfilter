/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include "cgen/runtime.h"
#include "ct/bpf/helpers.h"
#include "ct/bpf/key.h"
#include "ct/bpf/maps.h"
#include "ct/bpf/parse.h"
#include "ct/bpf/rate.h"
#include "ct/bpf/state.h"
#include "ct/bpf/stats.h"

static __always_inline __u8
bf_ct_bpf_initial_tcp_state(const struct bf_ct_pkt_info *pkt)
{
    if (pkt->tcp && pkt->tcp->syn && !pkt->tcp->ack)
        return CT_TCP_SYN_SENT;
    return CT_TCP_NONE;
}

static __always_inline __u8
bf_ct_bpf_initial_sctp_state(const struct bf_ct_pkt_info *pkt)
{
    if (pkt->sctp_chunk == BF_CT_SCTP_CID_INIT)
        return CT_SCTP_INIT;
    return CT_SCTP_NONE;
}

static __always_inline __u8
bf_ct_bpf_create_entry_v4(struct bf_runtime *ctx,
                          const struct bf_ct_pkt_info *pkt,
                          struct ct_key_v4 *key, __u8 orig_lo_is_src)
{
    struct ct_entry entry = {};
    struct ct_ip_key ip_key = {};
    void *flow_map;
    __u64 now_ns;
    int r;

    now_ns = bpf_ktime_get_ns();
    bf_ct_bpf_ip_key_from_v4(pkt->src_v4, &ip_key);

    if (bf_ct_bpf_rate_check((void *)&bf_ct_map_src_rate, &ip_key, pkt->proto,
                             now_ns)) {
        bf_ct_bpf_stats_rate_drop((void *)&bf_ct_map_stats);
        return 0;
    }

    if (bf_ct_bpf_src_count_check((void *)&bf_ct_map_src_count, &ip_key,
                                  pkt->proto)) {
        bf_ct_bpf_stats_count_drop((void *)&bf_ct_map_stats);
        return 0;
    }

    entry.last_seen_ns = now_ns;
    entry.created_ns = now_ns;
    entry.proto = pkt->proto;
    entry.orig_lo_is_src = orig_lo_is_src;
    entry.orig_discriminator = key->discriminator;
    entry.orig_src_ip = pkt->src_v4;
    entry.orig_dst_ip = pkt->dst_v4;
    entry.rx_packets = 1;
    entry.rx_bytes = ctx->pkt_size;

    if (pkt->proto == IPPROTO_TCP)
        entry.internal_state = bf_ct_bpf_initial_tcp_state(pkt);
    else if (pkt->proto == IPPROTO_SCTP)
        entry.internal_state = bf_ct_bpf_initial_sctp_state(pkt);

    flow_map = bf_ct_bpf_flow_map_global(0, pkt->proto);
    {
        /* Insert with a local key copy so the map operand stays a constant
         * map pointer (the relocatable global), independent of the call
         * frame's spilled stack contents. */
        struct ct_key_v4 local = *key;

        r = bpf_map_update_elem(flow_map, &local, &entry, BPF_NOEXIST);
    }
    if (r)
        return 0;

    bf_ct_bpf_src_count_inc((void *)&bf_ct_map_src_count, &ip_key);
    bf_ct_bpf_stats_new((void *)&bf_ct_map_stats, pkt->proto);
    return 1;
}

static __always_inline __u8
bf_ct_bpf_create_entry_v6(struct bf_runtime *ctx,
                          const struct bf_ct_pkt_info *pkt,
                          struct ct_key_v6 *key, __u8 orig_lo_is_src)
{
    struct ct_entry entry = {};
    struct ct_ip_key ip_key = {};
    void *flow_map;
    __u64 now_ns;
    int r;

    now_ns = bpf_ktime_get_ns();
    bf_ct_bpf_ip_key_from_v6(&pkt->src_v6, &ip_key);

    if (bf_ct_bpf_rate_check((void *)&bf_ct_map_src_rate, &ip_key, pkt->proto,
                             now_ns)) {
        bf_ct_bpf_stats_rate_drop((void *)&bf_ct_map_stats);
        return 0;
    }

    if (bf_ct_bpf_src_count_check((void *)&bf_ct_map_src_count, &ip_key,
                                  pkt->proto)) {
        bf_ct_bpf_stats_count_drop((void *)&bf_ct_map_stats);
        return 0;
    }

    entry.last_seen_ns = now_ns;
    entry.created_ns = now_ns;
    entry.proto = pkt->proto;
    entry.orig_lo_is_src = orig_lo_is_src;
    entry.orig_discriminator = key->discriminator;
    __builtin_memcpy(&entry.orig_src_ip, &pkt->src_v6.s6_addr[12], 4);
    __builtin_memcpy(&entry.orig_dst_ip, &pkt->dst_v6.s6_addr[12], 4);
    entry.rx_packets = 1;
    entry.rx_bytes = ctx->pkt_size;

    if (pkt->proto == IPPROTO_TCP)
        entry.internal_state = bf_ct_bpf_initial_tcp_state(pkt);
    else if (pkt->proto == IPPROTO_SCTP)
        entry.internal_state = bf_ct_bpf_initial_sctp_state(pkt);

    flow_map = bf_ct_bpf_flow_map_global(1, pkt->proto);
    {
        /* See bf_ct_bpf_create_entry_v4(): insert with a local key copy. */
        struct ct_key_v6 local = *key;

        r = bpf_map_update_elem(flow_map, &local, &entry, BPF_NOEXIST);
    }
    if (r)
        return 0;

    bf_ct_bpf_src_count_inc((void *)&bf_ct_map_src_count, &ip_key);
    bf_ct_bpf_stats_new((void *)&bf_ct_map_stats, pkt->proto);
    return 1;
}

static __always_inline __u8
bf_ct_bpf_create_if_new(struct bf_runtime *ctx, __u8 ct_state, __u8 is_v6,
                        struct ct_key_v4 *key_v4, struct ct_key_v6 *key_v6)
{
    struct bf_ct_pkt_info pkt = {};
    __u8 orig_lo_is_src = 0;

    if (ct_state != CT_STATE_NEW || !ctx)
        return 0;

    if (bf_ct_bpf_parse_runtime(ctx, &pkt) < 0)
        return 0;

    if (is_v6) {
        __u32 src_disc = pkt.sport;
        __u32 dst_disc = pkt.dport;

        if (pkt.proto == IPPROTO_ICMPV6)
            src_disc = pkt.icmp_id;
        else if (pkt.proto == IPPROTO_ESP || pkt.proto == IPPROTO_AH)
            src_disc = pkt.spi;
        else if (pkt.proto == IPPROTO_GRE)
            src_disc = pkt.gre_key;

        bf_ct_bpf_key_normalize_v6(&pkt.src_v6, &pkt.dst_v6, src_disc,
                                   dst_disc, pkt.proto, key_v6,
                                   &orig_lo_is_src);
        return bf_ct_bpf_create_entry_v6(ctx, &pkt, key_v6, orig_lo_is_src);
    }

    {
        __u32 src_disc = pkt.sport;
        __u32 dst_disc = pkt.dport;

        if (pkt.proto == IPPROTO_ICMP)
            src_disc = pkt.icmp_id;
        else if (pkt.proto == IPPROTO_ESP || pkt.proto == IPPROTO_AH)
            src_disc = pkt.spi;
        else if (pkt.proto == IPPROTO_GRE)
            src_disc = pkt.gre_key;

        bf_ct_bpf_key_normalize_v4(pkt.src_v4, pkt.dst_v4, src_disc, dst_disc,
                                   pkt.proto, key_v4, &orig_lo_is_src);
        return bf_ct_bpf_create_entry_v4(ctx, &pkt, key_v4, orig_lo_is_src);
    }
}
