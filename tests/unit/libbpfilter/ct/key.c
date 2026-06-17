// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>

#include <stddef.h>
#include <string.h>

#include "test.h"

static __be32 _be32(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    __be32 val;
    uint8_t *p = (uint8_t *)&val;

    p[0] = a;
    p[1] = b;
    p[2] = c;
    p[3] = d;

    return val;
}

static struct in6_addr _in6_raw(const uint8_t raw[16])
{
    struct in6_addr addr;

    memcpy(addr.s6_addr, raw, sizeof(addr.s6_addr));

    return addr;
}

static void struct_sizes(void **state)
{
    (void)state;

    assert_int_equal(sizeof(struct ct_key_v4), 16);
    assert_int_equal(sizeof(struct ct_key_v6), 40);
    assert_int_equal(sizeof(struct ct_entry), 64);
    assert_int_equal(sizeof(struct ct_rate_entry), 16);
    assert_int_equal(sizeof(struct ct_src_count_entry), 8);
    assert_int_equal(sizeof(struct ct_timeouts), 112);
    assert_int_equal(sizeof(struct ct_stats_counters), 96);
    assert_int_equal(sizeof(struct ct_ip_key), 16);
    assert_int_equal(sizeof(struct ct_spi_reverse_key), 16);
    assert_int_equal(sizeof(struct ct_tail_scratch), 44);
}

static void build_discriminator_tcp(void **state)
{
    (void)state;

    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_TCP, 443, 55000, 0, 0, 0, false),
        (443u << 16) | 55000u);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_TCP, 443, 55000, 0, 0, 0, true),
        (55000u << 16) | 443u);
}

static void build_discriminator_icmp(void **state)
{
    (void)state;

    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_ICMP, 0, 0, 1234, 0, 0, false),
        1234u);
}

static void build_discriminator_esp(void **state)
{
    (void)state;

    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_ESP, 0, 0, 0, 0xdeadbeef, 0, false),
        0xdeadbeefu);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_ESP, 0, 0, 0, 0xdeadbeef, 0, true),
        0xdeadbeefu);
}

static void build_discriminator_protocol_table(void **state)
{
    (void)state;

    /* §21.B protocol discriminator reference. */
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_UDP, 53, 12345, 0, 0, 0, false),
        (53u << 16) | 12345u);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_SCTP, 5000, 5001, 0, 0, 0, false),
        (5000u << 16) | 5001u);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_GRE, 0, 0, 0, 0, 0x00cafe00, false),
        0x00cafe00u);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_AH, 0, 0, 0, 0x12345678, 0, false),
        0x12345678u);
    assert_int_equal(
        bf_ct_build_discriminator(IPPROTO_ICMPV6, 0, 0, 4321, 0, 0, false),
        4321u);
    assert_int_equal(bf_ct_build_discriminator(99, 0, 0, 0, 0, 0, false), 0);
}

static void ct_entry_field_layout(void **state)
{
    (void)state;

    assert_int_equal(offsetof(struct ct_entry, orig_lo_is_src), 35);
    assert_int_equal(offsetof(struct ct_entry, orig_discriminator), 36);
    assert_int_equal(offsetof(struct ct_entry, reply_discriminator), 40);
}

static void normalize_icmpv6_bidirectional(void **state)
{
    struct ct_key_v6 fwd, rev;
    bool orig_fwd, orig_rev;
    static const uint8_t raw_a[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t raw_b[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 2};
    struct in6_addr a = _in6_raw(raw_a);
    struct in6_addr b = _in6_raw(raw_b);

    (void)state;

    assert_ok(bf_ct_key_normalize_v6(&a, &b, 1000, 0, IPPROTO_ICMPV6, &fwd,
                                     &orig_fwd));
    assert_ok(bf_ct_key_normalize_v6(&b, &a, 1000, 0, IPPROTO_ICMPV6, &rev,
                                     &orig_rev));

    assert_memory_equal(&fwd, &rev, sizeof(fwd));
    assert_int_equal(fwd.discriminator, 1000u);
    assert_int_equal(fwd.proto, IPPROTO_ICMPV6);
}

static void normalize_gre_spi_unchanged_on_swap(void **state)
{
    struct ct_key_v4 fwd, rev;
    bool orig_fwd, orig_rev;
    __be32 a = _be32(10, 0, 0, 1);
    __be32 b = _be32(10, 0, 0, 2);

    (void)state;

    assert_ok(bf_ct_key_normalize_v4(a, b, 0x00cafe00, 0, IPPROTO_GRE, &fwd,
                                     &orig_fwd));
    assert_ok(bf_ct_key_normalize_v4(b, a, 0x00cafe00, 0, IPPROTO_GRE, &rev,
                                     &orig_rev));

    assert_memory_equal(&fwd, &rev, sizeof(fwd));
    assert_int_equal(fwd.discriminator, 0x00cafe00u);
}

static void normalize_v4_bidirectional(void **state)
{
    struct ct_key_v4 fwd, rev;
    bool orig_fwd, orig_rev;
    __be32 a, b;

    (void)state;

    a = _be32(1, 2, 3, 4);
    b = _be32(10, 0, 0, 1);

    assert_ok(bf_ct_key_normalize_v4(a, b, 443, 55000, IPPROTO_TCP, &fwd,
                                     &orig_fwd));
    assert_ok(bf_ct_key_normalize_v4(b, a, 55000, 443, IPPROTO_TCP, &rev,
                                     &orig_rev));

    assert_memory_equal(&fwd, &rev, sizeof(fwd));
    assert_true(orig_fwd);
    assert_false(orig_rev);
    assert_int_equal(fwd.discriminator, (443u << 16) | 55000u);
}

static void normalize_v4_loopback_ports(void **state)
{
    struct ct_key_v4 lo, hi;
    bool orig_lo, orig_hi;
    __be32 addr = _be32(127, 0, 0, 1);

    (void)state;

    assert_ok(bf_ct_key_normalize_v4(addr, addr, 100, 200, IPPROTO_TCP, &lo,
                                     &orig_lo));
    assert_ok(bf_ct_key_normalize_v4(addr, addr, 200, 100, IPPROTO_TCP, &hi,
                                     &orig_hi));

    assert_memory_equal(&lo, &hi, sizeof(lo));
    assert_int_equal(lo.discriminator, (100u << 16) | 200u);
    assert_true(orig_lo);
    assert_false(orig_hi);
}

static void normalize_v6_bidirectional(void **state)
{
    struct ct_key_v6 fwd, rev;
    bool orig_fwd, orig_rev;
    static const uint8_t raw_a[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t raw_b[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 2};
    struct in6_addr a = _in6_raw(raw_a);
    struct in6_addr b = _in6_raw(raw_b);

    (void)state;

    assert_ok(bf_ct_key_normalize_v6(&a, &b, 53, 12345, IPPROTO_UDP, &fwd,
                                     &orig_fwd));
    assert_ok(bf_ct_key_normalize_v6(&b, &a, 12345, 53, IPPROTO_UDP, &rev,
                                     &orig_rev));

    assert_memory_equal(&fwd, &rev, sizeof(fwd));
    assert_int_equal(fwd.discriminator, (53u << 16) | 12345u);
}

static void normalize_generic_zero_disc(void **state)
{
    struct ct_key_v4 key;
    bool orig;
    __be32 a = _be32(0, 0, 0, 1);
    __be32 b = _be32(0, 0, 0, 2);

    (void)state;

    assert_ok(bf_ct_key_normalize_v4(a, b, 0, 0, 99, &key, &orig));
    assert_int_equal(key.discriminator, 0);
    assert_int_equal(key.proto, 99);
}

static void timeouts_defaults(void **state)
{
    struct ct_timeouts t;

    (void)state;

    bf_ct_timeouts_defaults(&t);

    assert_int_equal(t.tcp_syn_ns, 30ULL * BF_CT_NS_PER_S);
    assert_int_equal(t.tcp_established_ns, 6ULL * 3600ULL * BF_CT_NS_PER_S);
    assert_int_equal(t.udp_established_ns, 180ULL * BF_CT_NS_PER_S);
    assert_int_equal(t.generic_ns, 600ULL * BF_CT_NS_PER_S);
}

static void ip_key_v4_mapped(void **state)
{
    struct ct_ip_key key;
    __be32 addr = _be32(192, 168, 1, 1);

    (void)state;

    bf_ct_ip_key_from_v4(addr, &key);
    assert_int_equal(key.addr.s6_addr[10], 0xff);
    assert_int_equal(key.addr.s6_addr[11], 0xff);
    assert_memory_equal(&key.addr.s6_addr[12], &addr, sizeof(addr));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(struct_sizes),
        cmocka_unit_test(build_discriminator_tcp),
        cmocka_unit_test(build_discriminator_icmp),
        cmocka_unit_test(build_discriminator_esp),
        cmocka_unit_test(build_discriminator_protocol_table),
        cmocka_unit_test(ct_entry_field_layout),
        cmocka_unit_test(normalize_v4_bidirectional),
        cmocka_unit_test(normalize_icmpv6_bidirectional),
        cmocka_unit_test(normalize_gre_spi_unchanged_on_swap),
        cmocka_unit_test(normalize_v4_loopback_ports),
        cmocka_unit_test(normalize_v6_bidirectional),
        cmocka_unit_test(normalize_generic_zero_disc),
        cmocka_unit_test(timeouts_defaults),
        cmocka_unit_test(ip_key_v4_mapped),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
