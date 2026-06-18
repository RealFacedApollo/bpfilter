/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include "ct/bpf/helpers.h"
#include "cgen/runtime.h"
#include "ct/bpf/ipsec.h"
#include "ct/bpf/key.h"
#include "ct/bpf/parse.h"
#include "ct/bpf/related.h"
#include "ct/bpf/state.h"
#include "ct/bpf/stats.h"

static __always_inline struct ct_entry *
bf_ct_bpf_lookup_entry_v4(const struct bf_ct_bpf_maps *maps,
                          struct ct_key_v4 *key, __u8 proto, __u32 spi)
{
    /* Look up with a local copy of the key. Passing the caller-frame key
     * pointer (&ctx->ct_key_v4) to bpf_map_lookup_elem() makes the verifier
     * scalarize the caller frame's spilled map pointers, breaking every
     * subsequent map access in the subprogram. */
    struct ct_key_v4 local = *key;
    struct ct_spi_reverse_key rev_key = {};
    struct ct_entry *entry;
    void *map = bf_ct_bpf_flow_map(maps, 0, proto);
    __u32 *orig_spi;

    entry = bpf_map_lookup_elem(map, &local);
    if (entry)
        return entry;

    if (proto != IPPROTO_ESP && proto != IPPROTO_AH)
        return NULL;

    rev_key.lo_ip = local.lo_ip;
    rev_key.hi_ip = local.hi_ip;
    rev_key.reply_spi = spi;
    rev_key.proto = proto;

    orig_spi = bpf_map_lookup_elem(maps->spi_reverse, &rev_key);
    if (!orig_spi)
        return NULL;

    local.discriminator = *orig_spi;
    key->discriminator = *orig_spi;
    return bpf_map_lookup_elem(map, &local);
}

static __always_inline struct ct_entry *
bf_ct_bpf_lookup_entry_v6(const struct bf_ct_bpf_maps *maps,
                          struct ct_key_v6 *key, __u8 proto, __u32 spi)
{
    /* See bf_ct_bpf_lookup_entry_v4(): look up with a local key copy so the
     * caller-frame map pointers stay valid. */
    struct ct_key_v6 local = *key;
    struct ct_spi_reverse_key rev_key = {};
    struct ct_entry *entry;
    void *map = bf_ct_bpf_flow_map(maps, 1, proto);
    __u32 *orig_spi;

    entry = bpf_map_lookup_elem(map, &local);
    if (entry)
        return entry;

    if (proto != IPPROTO_ESP && proto != IPPROTO_AH)
        return NULL;

    __builtin_memcpy(&rev_key.lo_ip, &local.lo_ip.s6_addr[12], sizeof(__be32));
    __builtin_memcpy(&rev_key.hi_ip, &local.hi_ip.s6_addr[12], sizeof(__be32));
    rev_key.reply_spi = spi;
    rev_key.proto = proto;

    orig_spi = bpf_map_lookup_elem(maps->spi_reverse, &rev_key);
    if (!orig_spi)
        return NULL;

    local.discriminator = *orig_spi;
    key->discriminator = *orig_spi;
    return bpf_map_lookup_elem(map, &local);
}

static __always_inline __u8
bf_ct_bpf_lookup_hit(struct ct_entry *entry, __u8 is_reply, __u64 now_ns,
                     __u32 pkt_len, void *stats_map, void *spi_reverse_map,
                     __be32 lo_ip, __be32 hi_ip, __u8 proto, __u32 pkt_spi)
{
    if (entry->flags & CT_FLAG_DYING)
        return CT_STATE_NEW;

    if (entry->flags & CT_FLAG_INVALID) {
        bf_ct_bpf_stats_invalid(stats_map);
        return CT_STATE_INVALID;
    }

    entry->last_seen_ns = now_ns;

    if (is_reply) {
        entry->tx_packets += 1;
        entry->tx_bytes += pkt_len;
        if (!(entry->flags & CT_FLAG_SEEN_REPLY)) {
            entry->flags |= CT_FLAG_SEEN_REPLY | CT_FLAG_ASSURED;
            bf_ct_bpf_stats_established(stats_map);
        }
        if ((proto == IPPROTO_ESP || proto == IPPROTO_AH) && spi_reverse_map)
            bf_ct_bpf_ipsec_record_reply(entry, spi_reverse_map, lo_ip, hi_ip,
                                         proto, pkt_spi);
    } else {
        entry->rx_packets += 1;
        entry->rx_bytes += pkt_len;
    }

    return bf_ct_entry_to_rule_state(entry, is_reply);
}

static __always_inline __u8 bf_ct_bpf_lookup(struct bf_runtime *ctx,
                                             struct bf_ct_bpf_maps *maps,
                                             struct ct_key_v4 *key_v4,
                                             struct ct_key_v6 *key_v6,
                                             __u8 *is_reply)
{
    struct bf_ct_pkt_info pkt = {};
    struct ct_entry *entry = NULL;
    __u64 now_ns;
    __u8 orig_lo_is_src = 0;
    __u8 state;

    if (!ctx || !maps || bf_ct_bpf_parse_runtime(ctx, &pkt) < 0)
        return CT_STATE_INVALID;

    if (bf_ct_bpf_is_related_icmp_packet(&pkt))
        return bf_ct_bpf_lookup_related(ctx, maps, &pkt);

    now_ns = bpf_ktime_get_ns();

    if (pkt.is_v6) {
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
        *is_reply = bf_ct_bpf_is_reply_v6(&pkt.src_v6, orig_lo_is_src,
                                          &key_v6->lo_ip, &key_v6->hi_ip);

        entry = bf_ct_bpf_lookup_entry_v6(maps, key_v6, pkt.proto, pkt.spi);
        if (!entry) {
            if (bf_ct_bpf_tcp_unsolicited_ack(&pkt)) {
                bf_ct_bpf_stats_invalid(maps->stats);
                return CT_STATE_INVALID;
            }
            return CT_STATE_NEW;
        }

        {
            __be32 lo_ip;
            __be32 hi_ip;

            *is_reply = bf_ct_bpf_is_reply_v6(
                &pkt.src_v6, entry->orig_lo_is_src, &key_v6->lo_ip,
                &key_v6->hi_ip);
            __builtin_memcpy(&lo_ip, &key_v6->lo_ip.s6_addr[12],
                             sizeof(__be32));
            __builtin_memcpy(&hi_ip, &key_v6->hi_ip.s6_addr[12],
                             sizeof(__be32));
            state = bf_ct_bpf_lookup_hit(entry, *is_reply, now_ns, ctx->pkt_size,
                                         maps->stats, maps->spi_reverse, lo_ip,
                                         hi_ip, pkt.proto, pkt.spi);
        }
        key_v4->proto = 0;
        return state;
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
        *is_reply = bf_ct_bpf_is_reply_v4(pkt.src_v4, orig_lo_is_src,
                                          key_v4->lo_ip, key_v4->hi_ip);

        entry = bf_ct_bpf_lookup_entry_v4(maps, key_v4, pkt.proto, pkt.spi);
        if (!entry) {
            if (bf_ct_bpf_tcp_unsolicited_ack(&pkt)) {
                bf_ct_bpf_stats_invalid(maps->stats);
                return CT_STATE_INVALID;
            }
            return CT_STATE_NEW;
        }

        *is_reply = bf_ct_bpf_is_reply_v4(pkt.src_v4, entry->orig_lo_is_src,
                                          key_v4->lo_ip, key_v4->hi_ip);
        state = bf_ct_bpf_lookup_hit(entry, *is_reply, now_ns, ctx->pkt_size,
                                     maps->stats, maps->spi_reverse,
                                     key_v4->lo_ip, key_v4->hi_ip, pkt.proto,
                                     pkt.spi);
        key_v6->proto = 0;
        return state;
    }
}
