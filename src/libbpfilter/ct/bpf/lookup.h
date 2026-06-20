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
#include "ct/bpf/maps.h"
#include "ct/bpf/parse.h"
#include "ct/bpf/related.h"
#include "ct/bpf/state.h"
#include "ct/bpf/stats.h"

static __always_inline struct ct_entry *
bf_ct_bpf_lookup_entry_v4(struct ct_key_v4 *key, __u8 proto, __u32 spi)
{
    /* Look up with a local copy of the key. The flow and spi-reverse maps are
     * referenced as relocatable globals (bf_ct_bpf_flow_map_global,
     * &bf_ct_map_spi_reverse), so each map operand is a BPF_LD_MAP_FD constant
     * the verifier always trusts — independent of the call frame. The key copy
     * and the reverse key are staged in the per-CPU scratch map rather than on
     * this subprogram's stack, to keep the combined BPF stack within budget. */
    struct ct_subprog_scratch *s = bf_ct_bpf_scratch();
    struct ct_key_v4 *local;
    struct ct_spi_reverse_key *rev_key;
    struct ct_entry *entry;
    void *map = bf_ct_bpf_flow_map_global(0, proto);
    __u32 *orig_spi;

    if (!s)
        return NULL;
    local = &s->local.key_v4;
    *local = *key;

    entry = bpf_map_lookup_elem(map, local);
    if (entry)
        return entry;

    if (proto != IPPROTO_ESP && proto != IPPROTO_AH)
        return NULL;

    rev_key = &s->rev_key;
    __builtin_memset(rev_key, 0, sizeof(*rev_key));
    rev_key->lo_ip = local->lo_ip;
    rev_key->hi_ip = local->hi_ip;
    rev_key->reply_spi = spi;
    rev_key->proto = proto;

    orig_spi = bpf_map_lookup_elem((void *)&bf_ct_map_spi_reverse, rev_key);
    if (!orig_spi)
        return NULL;

    local->discriminator = *orig_spi;
    key->discriminator = *orig_spi;
    return bpf_map_lookup_elem(map, local);
}

static __always_inline struct ct_entry *
bf_ct_bpf_lookup_entry_v6(struct ct_key_v6 *key, __u8 proto, __u32 spi)
{
    /* See bf_ct_bpf_lookup_entry_v4(): maps are referenced as relocatable
     * globals, and the key copy / reverse key are staged in the scratch map. */
    struct ct_subprog_scratch *s = bf_ct_bpf_scratch();
    struct ct_key_v6 *local;
    struct ct_spi_reverse_key *rev_key;
    struct ct_entry *entry;
    void *map = bf_ct_bpf_flow_map_global(1, proto);
    __u32 *orig_spi;

    if (!s)
        return NULL;
    local = &s->local.key_v6;
    *local = *key;

    entry = bpf_map_lookup_elem(map, local);
    if (entry)
        return entry;

    if (proto != IPPROTO_ESP && proto != IPPROTO_AH)
        return NULL;

    rev_key = &s->rev_key;
    __builtin_memset(rev_key, 0, sizeof(*rev_key));
    __builtin_memcpy(&rev_key->lo_ip, &local->lo_ip.s6_addr[12],
                     sizeof(__be32));
    __builtin_memcpy(&rev_key->hi_ip, &local->hi_ip.s6_addr[12],
                     sizeof(__be32));
    rev_key->reply_spi = spi;
    rev_key->proto = proto;

    orig_spi = bpf_map_lookup_elem((void *)&bf_ct_map_spi_reverse, rev_key);
    if (!orig_spi)
        return NULL;

    local->discriminator = *orig_spi;
    key->discriminator = *orig_spi;
    return bpf_map_lookup_elem(map, local);
}

static __always_inline __u8
bf_ct_bpf_lookup_hit(struct ct_entry *entry, __u8 is_reply, __u64 now_ns,
                     __u32 pkt_len, void *stats_map, void *spi_reverse_map,
                     __be32 lo_ip, __be32 hi_ip, __u8 proto, __u32 pkt_spi,
                     struct ct_spi_reverse_key *rev_key)
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
                                         proto, pkt_spi, rev_key);
    } else {
        entry->rx_packets += 1;
        entry->rx_bytes += pkt_len;
    }

    return bf_ct_entry_to_rule_state(entry, is_reply);
}

/* Advance the protocol FSM for a hit entry, using the L4 flags already parsed
 * into @pkt by bf_ct_bpf_parse_runtime(). This runs in the same subprogram as
 * the lookup, so @entry stays a verified map-value pointer and the flags are
 * plain scalars — no separate update stub and no packet dereference, which is
 * what the former CT_UPDATE_TCP/SCTP elfstub calls could not get past the
 * verifier. The rule-visible state was already derived by
 * bf_ct_bpf_lookup_hit() before this point, so advancing here keeps the
 * "classify, then advance" ordering of the original design. */
static __always_inline void
bf_ct_bpf_advance_fsm(struct ct_entry *entry, const struct bf_ct_pkt_info *pkt,
                      __u8 is_reply)
{
    if (pkt->proto == IPPROTO_TCP) {
        bf_ct_bpf_tcp_fsm(entry, pkt->tcp_syn, pkt->tcp_ack, pkt->tcp_rst,
                          pkt->tcp_fin, is_reply);
    } else if (pkt->proto == IPPROTO_SCTP) {
        bf_ct_bpf_sctp_fsm(entry, pkt->sctp_chunk, is_reply);
    }
}

static __always_inline __u8 bf_ct_bpf_lookup(struct bf_runtime *ctx,
                                             struct ct_key_v4 *key_v4,
                                             struct ct_key_v6 *key_v6,
                                             __u8 *is_reply)
{
    struct ct_subprog_scratch *s = bf_ct_bpf_scratch();
    struct bf_ct_pkt_info *pkt;
    struct ct_entry *entry = NULL;
    __u64 now_ns;
    __u8 orig_lo_is_src = 0;
    __u8 state;

    if (!ctx || !s)
        return CT_STATE_INVALID;

    /* The parsed packet fields are staged in the per-CPU scratch map rather
     * than on this subprogram's stack, to keep the combined BPF stack within
     * budget. */
    pkt = &s->pkt;
    if (bf_ct_bpf_parse_runtime(ctx, pkt) < 0)
        return CT_STATE_INVALID;

    if (bf_ct_bpf_is_related_icmp_packet(pkt))
        return bf_ct_bpf_lookup_related(ctx, pkt);

    now_ns = bpf_ktime_get_ns();

    if (pkt->is_v6) {
        __u32 src_disc = pkt->sport;
        __u32 dst_disc = pkt->dport;

        if (pkt->proto == IPPROTO_ICMPV6)
            src_disc = pkt->icmp_id;
        else if (pkt->proto == IPPROTO_ESP || pkt->proto == IPPROTO_AH)
            src_disc = pkt->spi;
        else if (pkt->proto == IPPROTO_GRE)
            src_disc = pkt->gre_key;

        bf_ct_bpf_key_normalize_v6(&pkt->src_v6, &pkt->dst_v6, src_disc,
                                   dst_disc, pkt->proto, key_v6,
                                   &orig_lo_is_src);
        /* Pass the normalized key fields directly to the inline reply check
         * rather than copying them into stack-local in6_addr temporaries; the
         * copies kept the subprogram's stack frame oversized. */
        *is_reply = bf_ct_bpf_is_reply_v6(&pkt->src_v6, orig_lo_is_src,
                                          &key_v6->lo_ip, &key_v6->hi_ip);

        entry = bf_ct_bpf_lookup_entry_v6(key_v6, pkt->proto, pkt->spi);
        if (!entry) {
            if (bf_ct_bpf_tcp_unsolicited_ack(pkt)) {
                bf_ct_bpf_stats_invalid((void *)&bf_ct_map_stats);
                return CT_STATE_INVALID;
            }
            return CT_STATE_NEW;
        }

        {
            __be32 lo_ip;
            __be32 hi_ip;

            *is_reply = bf_ct_bpf_is_reply_v6(&pkt->src_v6,
                                              entry->orig_lo_is_src,
                                              &key_v6->lo_ip, &key_v6->hi_ip);
            __builtin_memcpy(&lo_ip, &key_v6->lo_ip.s6_addr[12],
                             sizeof(__be32));
            __builtin_memcpy(&hi_ip, &key_v6->hi_ip.s6_addr[12],
                             sizeof(__be32));
            state = bf_ct_bpf_lookup_hit(entry, *is_reply, now_ns, ctx->pkt_size,
                                         (void *)&bf_ct_map_stats,
                                         (void *)&bf_ct_map_spi_reverse, lo_ip,
                                         hi_ip, pkt->proto, pkt->spi,
                                         &s->rev_key);
        }
        bf_ct_bpf_advance_fsm(entry, pkt, *is_reply);
        key_v4->proto = 0;
        return state;
    }

    {
        __u32 src_disc = pkt->sport;
        __u32 dst_disc = pkt->dport;

        if (pkt->proto == IPPROTO_ICMP)
            src_disc = pkt->icmp_id;
        else if (pkt->proto == IPPROTO_ESP || pkt->proto == IPPROTO_AH)
            src_disc = pkt->spi;
        else if (pkt->proto == IPPROTO_GRE)
            src_disc = pkt->gre_key;

        bf_ct_bpf_key_normalize_v4(pkt->src_v4, pkt->dst_v4, src_disc, dst_disc,
                                   pkt->proto, key_v4, &orig_lo_is_src);
        *is_reply = bf_ct_bpf_is_reply_v4(pkt->src_v4, orig_lo_is_src,
                                          key_v4->lo_ip, key_v4->hi_ip);

        entry = bf_ct_bpf_lookup_entry_v4(key_v4, pkt->proto, pkt->spi);
        if (!entry) {
            if (bf_ct_bpf_tcp_unsolicited_ack(pkt)) {
                bf_ct_bpf_stats_invalid((void *)&bf_ct_map_stats);
                return CT_STATE_INVALID;
            }
            return CT_STATE_NEW;
        }

        *is_reply = bf_ct_bpf_is_reply_v4(pkt->src_v4, entry->orig_lo_is_src,
                                          key_v4->lo_ip, key_v4->hi_ip);
        state = bf_ct_bpf_lookup_hit(entry, *is_reply, now_ns, ctx->pkt_size,
                                     (void *)&bf_ct_map_stats,
                                     (void *)&bf_ct_map_spi_reverse,
                                     key_v4->lo_ip, key_v4->hi_ip, pkt->proto,
                                     pkt->spi, &s->rev_key);
        bf_ct_bpf_advance_fsm(entry, pkt, *is_reply);
        key_v6->proto = 0;
        return state;
    }
}
