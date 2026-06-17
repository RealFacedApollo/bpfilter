// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/in.h>

#include <bpfilter/ct.h>

#include "test.h"

static struct ct_timeouts _timeouts(void)
{
    struct ct_timeouts t;

    bf_ct_timeouts_defaults(&t);
    return t;
}

static void timeout_unassured_tcp(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_TCP,
        .flags = 0,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.tcp_syn_ns);
}

static void timeout_unassured_sctp(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_SCTP,
        .flags = 0,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.sctp_init_ns);
}

static void timeout_unassured_udp(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_UDP,
        .flags = 0,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.udp_new_ns);
}

static void timeout_tcp_established(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_TCP,
        .flags = CT_FLAG_SEEN_REPLY,
        .internal_state = CT_TCP_ESTABLISHED,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.tcp_established_ns);
}

static void timeout_tcp_fin_wait(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_TCP,
        .flags = CT_FLAG_SEEN_REPLY,
        .internal_state = CT_TCP_FIN_WAIT,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.tcp_fin_wait_ns);
}

static void timeout_udp_established(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_UDP,
        .flags = CT_FLAG_SEEN_REPLY,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.udp_established_ns);
}

static void timeout_icmp(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = IPPROTO_ICMP,
        .flags = CT_FLAG_SEEN_REPLY,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.icmp_ns);
}

static void timeout_generic(void **state)
{
    struct ct_timeouts t = _timeouts();
    struct ct_entry e = {
        .proto = 89,
        .flags = CT_FLAG_SEEN_REPLY,
    };

    (void)state;

    assert_int_equal(bf_ct_get_timeout_ns(&e, &t), t.generic_ns);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(timeout_unassured_tcp),
        cmocka_unit_test(timeout_unassured_sctp),
        cmocka_unit_test(timeout_unassured_udp),
        cmocka_unit_test(timeout_tcp_established),
        cmocka_unit_test(timeout_tcp_fin_wait),
        cmocka_unit_test(timeout_udp_established),
        cmocka_unit_test(timeout_icmp),
        cmocka_unit_test(timeout_generic),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
