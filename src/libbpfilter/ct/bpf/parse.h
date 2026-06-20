/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>

#include "cgen/runtime.h"

#define BF_CT_GRE_KEY 0x2000

struct bf_ct_gre_hdr
{
    __be16 flags;
    __be16 protocol;
};

/* The CT stubs run as a separate BPF subprogram. A header pointer obtained
 * from bpf_dynptr_slice() in the main program loses its verifier provenance
 * once it is spilled to the runtime struct and reloaded in the callee frame,
 * so the stub cannot dereference ctx->l3_hdr / ctx->l4_hdr directly. The main
 * program instead copies the header bytes into these embedded buffers (see
 * the CT prologue), which the stub reads as plain struct memory. */
static __always_inline const void *bf_ct_bpf_l3(const struct bf_runtime *ctx)
{
    return ctx->l3;
}

static __always_inline const void *bf_ct_bpf_l4(const struct bf_runtime *ctx)
{
#ifdef BF_CT_BPF_HARNESS
    /* The harness builds the runtime in a map value and stages large L4
     * headers (e.g. ICMP-error inner packets) in the scratch area. */
    if (ctx->l4_size <= BF_L4_SLICE_LEN)
        return ctx->l4;

    return ctx->scratch;
#else
    /* Real datapath: always read from the embedded l4 copy (filled by the CT
     * prologue). The scratch area can't be used as an L4 fallback here: it
     * doubles as the lookup-args buffer and holds spilled pointers, which the
     * verifier refuses to read back as packet data. */
    return ctx->l4;
#endif
}

static __always_inline __u32 bf_ct_bpf_parse_gre_key(const struct bf_runtime *ctx)
{
    const struct bf_ct_gre_hdr *gre;
    const void *l4 = bf_ct_bpf_l4(ctx);
    __u32 flags;

    if (!l4 || ctx->l4_size < sizeof(*gre))
        return 0;

    gre = l4;
    flags = bpf_ntohs(gre->flags);
    if (!(flags & BF_CT_GRE_KEY))
        return 0;

    if (ctx->l4_size < sizeof(*gre) + 4)
        return 0;

    return bpf_ntohl(*(__u32 *)(l4 + sizeof(*gre)));
}

/* struct bf_ct_pkt_info is defined in <bpfilter/ct.h>: it is staged in the
 * per-CPU ct_subprog_scratch map and must stay pointer-free. */

static __always_inline bool bf_ct_bpf_is_icmp_error(__u8 type)
{
    return type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED ||
           type == ICMP_PARAMETERPROB;
}

static __always_inline bool bf_ct_bpf_is_icmpv6_error(__u8 type)
{
    return type == ICMPV6_DEST_UNREACH || type == ICMPV6_PKT_TOOBIG ||
           type == ICMPV6_TIME_EXCEED || type == ICMPV6_PARAMPROB;
}

#define BF_CT_SCTP_COMMON_HDR_LEN 12

static __always_inline __u8
bf_ct_bpf_parse_sctp_chunk(const struct bf_runtime *ctx)
{
    const void *l4 = bf_ct_bpf_l4(ctx);
    __u8 chunk;

    if (!l4 || ctx->l4_size < BF_CT_SCTP_COMMON_HDR_LEN + 1)
        return 0;

    chunk = *(__u8 *)(l4 + BF_CT_SCTP_COMMON_HDR_LEN);
    return chunk;
}

static __always_inline __u32 bf_ct_bpf_parse_esp_spi(const struct bf_runtime *ctx)
{
    const void *l4 = bf_ct_bpf_l4(ctx);

    if (!l4 || ctx->l4_size < 4)
        return 0;

    return bpf_ntohl(*(__u32 *)l4);
}

static __always_inline int bf_ct_bpf_parse_runtime(const struct bf_runtime *ctx,
                                                   struct bf_ct_pkt_info *pkt)
{
    const struct iphdr *ip4;
    const struct ipv6hdr *ip6;
    const void *l3;
    const void *l4;

    if (!ctx || !pkt || ctx->l3_size < sizeof(struct iphdr))
        return -1;

    l3 = bf_ct_bpf_l3(ctx);
    if (!l3)
        return -1;

    __builtin_memset(pkt, 0, sizeof(*pkt));

    ip4 = l3;
    if (ip4->version == 4) {
        pkt->is_v6 = 0;
        pkt->proto = ip4->protocol;
        pkt->src_v4 = ip4->saddr;
        pkt->dst_v4 = ip4->daddr;

        if (!ctx->l4_size)
            return 0;

        l4 = bf_ct_bpf_l4(ctx);
        if (!l4)
            return 0;

        pkt->has_l4 = 1;

        switch (pkt->proto) {
        case IPPROTO_TCP: {
            const struct tcphdr *tcp = l4;

            pkt->sport = bpf_ntohs(tcp->source);
            pkt->dport = bpf_ntohs(tcp->dest);
            pkt->tcp_syn = tcp->syn;
            pkt->tcp_ack = tcp->ack;
            pkt->tcp_rst = tcp->rst;
            pkt->tcp_fin = tcp->fin;
            break;
        }
        case IPPROTO_UDP: {
            const struct udphdr *udp = l4;

            pkt->sport = bpf_ntohs(udp->source);
            pkt->dport = bpf_ntohs(udp->dest);
            break;
        }
        case IPPROTO_ICMP: {
            const struct icmphdr *icmp = l4;

            pkt->icmp_type = icmp->type;
            pkt->icmp_id = bpf_ntohs(icmp->un.echo.id);
            break;
        }
        case IPPROTO_SCTP:
            pkt->sctp_chunk = bf_ct_bpf_parse_sctp_chunk(ctx);
            if (ctx->l4_size >= 4) {
                const __u16 *ports = l4;

                pkt->sport = bpf_ntohs(ports[0]);
                pkt->dport = bpf_ntohs(ports[1]);
            }
            break;
        case IPPROTO_ESP:
        case IPPROTO_AH:
            pkt->spi = bf_ct_bpf_parse_esp_spi(ctx);
            break;
        case IPPROTO_GRE:
            pkt->gre_key = bf_ct_bpf_parse_gre_key(ctx);
            break;
        default:
            break;
        }

        return 0;
    }

    ip6 = l3;
    if (ip6->version != 6)
        return -1;

    pkt->is_v6 = 1;
    pkt->proto = ip6->nexthdr;
    pkt->src_v6 = ip6->saddr;
    pkt->dst_v6 = ip6->daddr;

    if (!ctx->l4_size)
        return 0;

    l4 = bf_ct_bpf_l4(ctx);
    if (!l4)
        return 0;

    pkt->has_l4 = 1;

    switch (pkt->proto) {
    case IPPROTO_TCP: {
        const struct tcphdr *tcp = l4;

        pkt->sport = bpf_ntohs(tcp->source);
        pkt->dport = bpf_ntohs(tcp->dest);
        pkt->tcp_syn = tcp->syn;
        pkt->tcp_ack = tcp->ack;
        pkt->tcp_rst = tcp->rst;
        pkt->tcp_fin = tcp->fin;
        break;
    }
    case IPPROTO_UDP: {
        const struct udphdr *udp = l4;

        pkt->sport = bpf_ntohs(udp->source);
        pkt->dport = bpf_ntohs(udp->dest);
        break;
    }
    case IPPROTO_ICMPV6: {
        const struct icmp6hdr *icmp6 = l4;

        pkt->icmp_type = icmp6->icmp6_type;
        pkt->icmp_id = bpf_ntohs(icmp6->icmp6_identifier);
        break;
    }
    case IPPROTO_SCTP:
        pkt->sctp_chunk = bf_ct_bpf_parse_sctp_chunk(ctx);
        if (ctx->l4_size >= 4) {
            const __u16 *ports = l4;

            pkt->sport = bpf_ntohs(ports[0]);
            pkt->dport = bpf_ntohs(ports[1]);
        }
        break;
    case IPPROTO_ESP:
    case IPPROTO_AH:
        pkt->spi = bf_ct_bpf_parse_esp_spi(ctx);
        break;
    case IPPROTO_GRE:
        pkt->gre_key = bf_ct_bpf_parse_gre_key(ctx);
        break;
    default:
        break;
    }

    return 0;
}

static __always_inline bool
bf_ct_bpf_is_related_icmp_packet(const struct bf_ct_pkt_info *pkt)
{
    if (!pkt->is_v6 && pkt->proto == IPPROTO_ICMP)
        return bf_ct_bpf_is_icmp_error(pkt->icmp_type);
    if (pkt->is_v6 && pkt->proto == IPPROTO_ICMPV6)
        return bf_ct_bpf_is_icmpv6_error(pkt->icmp_type);
    return false;
}

static __always_inline bool
bf_ct_bpf_tcp_unsolicited_ack(const struct bf_ct_pkt_info *pkt)
{
    if (!pkt->has_l4 || pkt->proto != IPPROTO_TCP)
        return false;

    return pkt->tcp_ack && !pkt->tcp_syn && !pkt->tcp_rst && !pkt->tcp_fin;
}
