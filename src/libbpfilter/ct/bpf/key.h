/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/in.h>
#include <linux/types.h>

#include <string.h>

static __always_inline __u32 bf_ct_bpf_pack_disc(__u32 lo, __u32 hi)
{
    return (lo << 16) | (hi & 0xffffu);
}

static __always_inline bool bf_ct_bpf_uses_port_disc(__u8 proto)
{
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
           proto == IPPROTO_SCTP;
}

static __always_inline bool bf_ct_bpf_uses_spi_disc(__u8 proto)
{
    return proto == IPPROTO_ESP || proto == IPPROTO_AH || proto == IPPROTO_GRE;
}

static __always_inline __u32
bf_ct_bpf_disc_from_parts(__u8 proto, __u32 src_disc, __u32 dst_disc,
                          bool swapped)
{
    if (bf_ct_bpf_uses_port_disc(proto)) {
        __u16 lo_port = swapped ? (__u16)dst_disc : (__u16)src_disc;
        __u16 hi_port = swapped ? (__u16)src_disc : (__u16)dst_disc;

        return bf_ct_bpf_pack_disc(lo_port, hi_port);
    }

    if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
        return src_disc & 0xffffu;

    if (bf_ct_bpf_uses_spi_disc(proto))
        return src_disc;

    return 0;
}

static __always_inline __u32 bf_ct_bpf_be32_to_host(__be32 val)
{
    const __u8 *b = (const __u8 *)&val;

    return ((__u32)b[0] << 24) | ((__u32)b[1] << 16) | ((__u32)b[2] << 8) |
           (__u32)b[3];
}

static __always_inline int bf_ct_bpf_compare_v4(__be32 a, __be32 b)
{
    __u32 na = bf_ct_bpf_be32_to_host(a);
    __u32 nb = bf_ct_bpf_be32_to_host(b);

    if (na < nb)
        return -1;
    if (na > nb)
        return 1;
    return 0;
}

static __always_inline int bf_ct_bpf_compare_v6(const struct in6_addr *a,
                                                const struct in6_addr *b)
{
    return __builtin_memcmp(a, b, sizeof(*a));
}

static __always_inline void
bf_ct_bpf_key_normalize_v4(__be32 src, __be32 dst, __u32 src_disc,
                           __u32 dst_disc, __u8 proto, struct ct_key_v4 *key,
                           __u8 *orig_lo_is_src)
{
    int cmp;
    bool swapped;

    __builtin_memset(key, 0, sizeof(*key));
    key->proto = proto;

    cmp = bf_ct_bpf_compare_v4(src, dst);
    if (cmp < 0) {
        key->lo_ip = src;
        key->hi_ip = dst;
        swapped = false;
        *orig_lo_is_src = 1;
    } else if (cmp > 0) {
        key->lo_ip = dst;
        key->hi_ip = src;
        swapped = true;
        *orig_lo_is_src = 0;
    } else {
        key->lo_ip = src;
        key->hi_ip = dst;

        if (bf_ct_bpf_uses_port_disc(proto)) {
            if ((__u16)src_disc <= (__u16)dst_disc) {
                swapped = false;
                *orig_lo_is_src = 1;
            } else {
                swapped = true;
                *orig_lo_is_src = 0;
            }
        } else {
            swapped = false;
            *orig_lo_is_src = 1;
        }
    }

    key->discriminator =
        bf_ct_bpf_disc_from_parts(proto, src_disc, dst_disc, swapped);
}

static __always_inline void
bf_ct_bpf_key_normalize_v6(const struct in6_addr *src,
                             const struct in6_addr *dst, __u32 src_disc,
                             __u32 dst_disc, __u8 proto, struct ct_key_v6 *key,
                             __u8 *orig_lo_is_src)
{
    int cmp;
    bool swapped;

    __builtin_memset(key, 0, sizeof(*key));
    key->proto = proto;

    cmp = bf_ct_bpf_compare_v6(src, dst);
    if (cmp < 0) {
        key->lo_ip = *src;
        key->hi_ip = *dst;
        swapped = false;
        *orig_lo_is_src = 1;
    } else if (cmp > 0) {
        key->lo_ip = *dst;
        key->hi_ip = *src;
        swapped = true;
        *orig_lo_is_src = 0;
    } else {
        key->lo_ip = *src;
        key->hi_ip = *dst;

        if (bf_ct_bpf_uses_port_disc(proto)) {
            if ((__u16)src_disc <= (__u16)dst_disc) {
                swapped = false;
                *orig_lo_is_src = 1;
            } else {
                swapped = true;
                *orig_lo_is_src = 0;
            }
        } else {
            swapped = false;
            *orig_lo_is_src = 1;
        }
    }

    key->discriminator =
        bf_ct_bpf_disc_from_parts(proto, src_disc, dst_disc, swapped);
}

static __always_inline void bf_ct_bpf_ip_key_from_v4(__be32 addr,
                                                     struct ct_ip_key *key)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->addr.s6_addr[10] = 0xff;
    key->addr.s6_addr[11] = 0xff;
    __builtin_memcpy(&key->addr.s6_addr[12], &addr, sizeof(addr));
}

static __always_inline void
bf_ct_bpf_ip_key_from_v6(const struct in6_addr *addr, struct ct_ip_key *key)
{
    key->addr = *addr;
}

static __always_inline bool bf_ct_bpf_is_reply_v4(__be32 src, __u8 orig_lo_is_src,
                                                  __be32 lo_ip, __be32 hi_ip)
{
    if (orig_lo_is_src)
        return src == hi_ip;
    return src == lo_ip;
}

static __always_inline bool
bf_ct_bpf_is_reply_v6(const struct in6_addr *src, __u8 orig_lo_is_src,
                      const struct in6_addr *lo_ip,
                      const struct in6_addr *hi_ip)
{
    if (orig_lo_is_src)
        return bf_ct_bpf_compare_v6(src, hi_ip) == 0;
    return bf_ct_bpf_compare_v6(src, lo_ip) == 0;
}
