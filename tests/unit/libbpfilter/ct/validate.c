/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/ct.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>

#include "test.h"

static void parse_mem_available(void **state)
{
    uint64_t kb = 0;

    (void)state;

    assert_ok(bf_ct_parse_mem_available_kb(
        "MemTotal:       8000000 kB\n"
        "MemAvailable:   1234567 kB\n",
        &kb));
    assert_int_equal(kb, 1234567);

    assert_err(bf_ct_parse_mem_available_kb("MemTotal: 1 kB\n", &kb));
}

static void estimate_map_bytes_defaults(void **state)
{
    uint64_t bytes;

    (void)state;

    bytes = bf_ct_estimate_map_bytes(NULL);
    assert_true(bytes > 0);
}

static void estimate_map_bytes_custom(void **state)
{
    struct bf_ct_maps_opts opts = {
        .max_tcp = 1024,
        .max_tcp6 = 1024,
        .max_any = 1024,
        .max_any6 = 1024,
        .max_src_rate = 128,
        .max_src_count = 128,
        .max_spi_reverse = 128,
    };
    uint64_t bytes;

    (void)state;

    bytes = bf_ct_estimate_map_bytes(&opts);
    assert_int_equal(bytes, 4ULL * 1024 * sizeof(struct ct_entry) +
                                128ULL * sizeof(struct ct_rate_entry) +
                                128ULL * sizeof(struct ct_src_count_entry) +
                                128ULL * sizeof(__u32));
}

static void timeouts_clamp_low(void **state)
{
    struct ct_timeouts t;

    (void)state;

    bf_ct_timeouts_defaults(&t);
    t.tcp_established_ns = 1;
    bf_ct_timeouts_clamp(&t);
    assert_int_equal(t.tcp_established_ns, 60ULL * BF_CT_NS_PER_S);
}

static void timeouts_clamp_high(void **state)
{
    struct ct_timeouts t;

    (void)state;

    bf_ct_timeouts_defaults(&t);
    t.udp_new_ns = 1000ULL * BF_CT_NS_PER_S;
    bf_ct_timeouts_clamp(&t);
    assert_int_equal(t.udp_new_ns, 300ULL * BF_CT_NS_PER_S);
}

static void timeouts_clamp_defaults_unchanged(void **state)
{
    struct ct_timeouts before;
    struct ct_timeouts after;

    (void)state;

    bf_ct_timeouts_defaults(&before);
    after = before;
    bf_ct_timeouts_clamp(&after);
    assert_memory_equal(&before, &after, sizeof(before));
}

static void hook_compat_tc_ok(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;

    (void)state;

    assert_ok(bf_chain_new(&chain, "tc", BF_HOOK_TC_INGRESS, BF_VERDICT_ACCEPT,
                           NULL, NULL));
    assert_ok(bf_ct_validate_hook_compat(chain));
}

static void hook_compat_xdp_rejects(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;

    (void)state;

    assert_ok(bf_chain_new(&chain, "xdp", BF_HOOK_XDP, BF_VERDICT_DROP, NULL,
                           NULL));
    chain->flags |= BF_FLAG(BF_CHAIN_CONNTRACK);
    assert_err(bf_ct_validate_hook_compat(chain));
}

static void warn_chain_policy_smoke(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    struct bf_match_ct_payload ct_new = {.state_mask = CT_STATE_NEW};
    struct bf_match_ct_payload ct_est =
        {.state_mask = CT_STATE_ESTABLISHED};

    (void)state;

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                  &ct_new, sizeof(ct_new), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                  &ct_est, sizeof(ct_est), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_chain_new(&chain, "warn_smoke", BF_HOOK_TC_INGRESS,
                           BF_VERDICT_DROP, NULL, &rules));
    bf_ct_warn_chain_policy(chain);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_mem_available),
        cmocka_unit_test(estimate_map_bytes_defaults),
        cmocka_unit_test(estimate_map_bytes_custom),
        cmocka_unit_test(timeouts_clamp_low),
        cmocka_unit_test(timeouts_clamp_high),
        cmocka_unit_test(timeouts_clamp_defaults_unchanged),
        cmocka_unit_test(hook_compat_tc_ok),
        cmocka_unit_test(hook_compat_xdp_rejects),
        cmocka_unit_test(warn_chain_policy_smoke),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
