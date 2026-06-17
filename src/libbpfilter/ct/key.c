// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

_Static_assert(sizeof(struct ct_key_v4) == 16, "ct_key_v4 must be 16 bytes");
_Static_assert(sizeof(struct ct_key_v6) == 40, "ct_key_v6 must be 40 bytes");
_Static_assert(sizeof(struct ct_entry) == 64, "ct_entry must be 64 bytes");

static __u32 _bf_ct_pack_disc(__u32 lo, __u32 hi)
{
    return (lo << 16) | (hi & 0xffffu);
}

static bool _bf_ct_uses_port_disc(__u8 proto)
{
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP;
}

static bool _bf_ct_uses_spi_disc(__u8 proto)
{
    return proto == IPPROTO_ESP || proto == IPPROTO_AH || proto == IPPROTO_GRE;
}

static __u32 _bf_ct_disc_from_parts(__u8 proto, __u32 src_disc, __u32 dst_disc,
                                    bool swapped)
{
    if (_bf_ct_uses_port_disc(proto)) {
        __u16 lo_port = swapped ? (__u16)dst_disc : (__u16)src_disc;
        __u16 hi_port = swapped ? (__u16)src_disc : (__u16)dst_disc;

        return _bf_ct_pack_disc(lo_port, hi_port);
    }

    if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
        return src_disc & 0xffffu;

    if (_bf_ct_uses_spi_disc(proto))
        return src_disc;

    return 0;
}

__u32 bf_ct_build_discriminator(__u8 proto, __u16 sport, __u16 dport,
                               __u16 icmp_id, __u32 spi, __u32 gre_key,
                               bool swapped)
{
    switch (proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
        return _bf_ct_disc_from_parts(proto, sport, dport, swapped);
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return icmp_id;
    case IPPROTO_ESP:
    case IPPROTO_AH:
        return spi;
    case IPPROTO_GRE:
        return gre_key;
    default:
        return 0;
    }
}

void bf_ct_timeouts_defaults(struct ct_timeouts *timeouts)
{
    assert(timeouts);

    memset(timeouts, 0, sizeof(*timeouts));

    timeouts->tcp_syn_ns = 30ULL * BF_CT_NS_PER_S;
    timeouts->tcp_established_ns = 6ULL * 3600ULL * BF_CT_NS_PER_S;
    timeouts->tcp_fin_wait_ns = 120ULL * BF_CT_NS_PER_S;
    timeouts->tcp_time_wait_ns = 120ULL * BF_CT_NS_PER_S;
    timeouts->tcp_close_ns = 10ULL * BF_CT_NS_PER_S;
    timeouts->udp_new_ns = 30ULL * BF_CT_NS_PER_S;
    timeouts->udp_established_ns = 180ULL * BF_CT_NS_PER_S;
    timeouts->icmp_ns = 30ULL * BF_CT_NS_PER_S;
    timeouts->sctp_init_ns = 30ULL * BF_CT_NS_PER_S;
    timeouts->sctp_established_ns = 3600ULL * BF_CT_NS_PER_S;
    timeouts->sctp_shutdown_ns = 60ULL * BF_CT_NS_PER_S;
    timeouts->ipsec_ns = 3600ULL * BF_CT_NS_PER_S;
    timeouts->gre_ns = 300ULL * BF_CT_NS_PER_S;
    timeouts->generic_ns = 600ULL * BF_CT_NS_PER_S;
}

void bf_ct_ip_key_from_v4(__be32 addr, struct ct_ip_key *key)
{
    assert(key);

    memset(key, 0, sizeof(*key));
    key->addr.s6_addr[10] = 0xff;
    key->addr.s6_addr[11] = 0xff;
    memcpy(&key->addr.s6_addr[12], &addr, sizeof(addr));
}

void bf_ct_ip_key_from_v6(const struct in6_addr *addr, struct ct_ip_key *key)
{
    assert(addr);
    assert(key);

    key->addr = *addr;
}

static uint32_t _bf_ct_be32_to_host(__be32 val)
{
    const uint8_t *b = (const uint8_t *)&val;

    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static int _bf_ct_compare_v4(__be32 a, __be32 b)
{
    uint32_t na = _bf_ct_be32_to_host(a);
    uint32_t nb = _bf_ct_be32_to_host(b);

    if (na < nb)
        return -1;
    if (na > nb)
        return 1;
    return 0;
}

static int _bf_ct_compare_v6(const struct in6_addr *a, const struct in6_addr *b)
{
    return memcmp(a, b, sizeof(*a));
}

int bf_ct_key_normalize_v4(__be32 src, __be32 dst, __u32 src_disc,
                           __u32 dst_disc, __u8 proto, struct ct_key_v4 *key,
                           bool *orig_lo_is_src)
{
    int cmp;
    bool swapped;

    if (!key || !orig_lo_is_src)
        return -EINVAL;

    memset(key, 0, sizeof(*key));
    key->proto = proto;

    cmp = _bf_ct_compare_v4(src, dst);
    if (cmp < 0) {
        key->lo_ip = src;
        key->hi_ip = dst;
        swapped = false;
        *orig_lo_is_src = true;
    } else if (cmp > 0) {
        key->lo_ip = dst;
        key->hi_ip = src;
        swapped = true;
        *orig_lo_is_src = false;
    } else {
        key->lo_ip = src;
        key->hi_ip = dst;

        if (_bf_ct_uses_port_disc(proto)) {
            if ((__u16)src_disc <= (__u16)dst_disc) {
                swapped = false;
                *orig_lo_is_src = true;
            } else {
                swapped = true;
                *orig_lo_is_src = false;
            }
        } else {
            swapped = false;
            *orig_lo_is_src = true;
        }
    }

    key->discriminator =
        _bf_ct_disc_from_parts(proto, src_disc, dst_disc, swapped);

    return 0;
}

int bf_ct_key_normalize_v6(const struct in6_addr *src,
                           const struct in6_addr *dst, __u32 src_disc,
                           __u32 dst_disc, __u8 proto, struct ct_key_v6 *key,
                           bool *orig_lo_is_src)
{
    int cmp;
    bool swapped;

    if (!src || !dst || !key || !orig_lo_is_src)
        return -EINVAL;

    memset(key, 0, sizeof(*key));
    key->proto = proto;

    cmp = _bf_ct_compare_v6(src, dst);
    if (cmp < 0) {
        key->lo_ip = *src;
        key->hi_ip = *dst;
        swapped = false;
        *orig_lo_is_src = true;
    } else if (cmp > 0) {
        key->lo_ip = *dst;
        key->hi_ip = *src;
        swapped = true;
        *orig_lo_is_src = false;
    } else {
        key->lo_ip = *src;
        key->hi_ip = *dst;

        if (_bf_ct_uses_port_disc(proto)) {
            if ((__u16)src_disc <= (__u16)dst_disc) {
                swapped = false;
                *orig_lo_is_src = true;
            } else {
                swapped = true;
                *orig_lo_is_src = false;
            }
        } else {
            swapped = false;
            *orig_lo_is_src = true;
        }
    }

    key->discriminator =
        _bf_ct_disc_from_parts(proto, src_disc, dst_disc, swapped);

    return 0;
}
