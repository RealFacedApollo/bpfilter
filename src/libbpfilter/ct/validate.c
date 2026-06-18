/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/chain.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/verdict.h>

#define _BF_CT_MAP_MIN_ENTRIES 16384u
#define _BF_CT_MEM_FRACTION_NUM 1u
#define _BF_CT_MEM_FRACTION_DEN 4u

struct _bf_ct_timeout_bound
{
    const char *name;
    size_t offset;
    __u64 min_ns;
    __u64 max_ns;
};

#define _BF_CT_TIMEOUT_BOUND(field, min_s, max_s)                              \
    {                                                                          \
        .name = #field,                                                        \
        .offset = offsetof(struct ct_timeouts, field),                           \
        .min_ns = (min_s) * BF_CT_NS_PER_S,                                    \
        .max_ns = (max_s) * BF_CT_NS_PER_S,                                    \
    }

static const struct _bf_ct_timeout_bound _bf_ct_timeout_bounds[] = {
    _BF_CT_TIMEOUT_BOUND(tcp_syn_ns, 1, 300),
    _BF_CT_TIMEOUT_BOUND(tcp_established_ns, 60, 86400),
    _BF_CT_TIMEOUT_BOUND(tcp_fin_wait_ns, 10, 600),
    _BF_CT_TIMEOUT_BOUND(tcp_time_wait_ns, 10, 600),
    _BF_CT_TIMEOUT_BOUND(tcp_close_ns, 1, 300),
    _BF_CT_TIMEOUT_BOUND(udp_new_ns, 1, 300),
    _BF_CT_TIMEOUT_BOUND(udp_established_ns, 10, 3600),
    _BF_CT_TIMEOUT_BOUND(icmp_ns, 1, 300),
    _BF_CT_TIMEOUT_BOUND(sctp_init_ns, 1, 300),
    _BF_CT_TIMEOUT_BOUND(sctp_established_ns, 60, 86400),
    _BF_CT_TIMEOUT_BOUND(sctp_shutdown_ns, 10, 600),
    _BF_CT_TIMEOUT_BOUND(ipsec_ns, 60, 86400),
    _BF_CT_TIMEOUT_BOUND(gre_ns, 10, 3600),
    _BF_CT_TIMEOUT_BOUND(generic_ns, 10, 86400),
};

static uint32_t _bf_ct_opt_or_default(uint32_t opt, uint32_t def)
{
    return opt ? opt : def;
}

static bool _bf_ct_state_matches(uint8_t state_mask, uint8_t state, bool invert)
{
    bool match = (state_mask & state) != 0;

    return invert ? !match : match;
}

static bool _bf_ct_rule_has_ct_matcher(const struct bf_rule *rule)
{
    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_matcher_get_type(matcher) == BF_MATCHER_CONNTRACK)
            return true;
    }

    return false;
}

static bool _bf_ct_rule_matches_ct_state(const struct bf_rule *rule,
                                         uint8_t state)
{
    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        const struct bf_match_ct_payload *ct;

        if (bf_matcher_get_type(matcher) != BF_MATCHER_CONNTRACK)
            continue;

        ct = bf_matcher_payload(matcher);
        if (_bf_ct_state_matches(ct->state_mask, state, ct->invert))
            return true;
    }

    return false;
}

static bool _bf_ct_chain_has_ct_matcher(const struct bf_chain *chain)
{
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->disabled)
            continue;
        if (_bf_ct_rule_has_ct_matcher(rule))
            return true;
    }

    return false;
}

bool bf_ct_chain_consumes_ct(const struct bf_chain *chain)
{
    assert(chain);

    return _bf_ct_chain_has_ct_matcher(chain);
}

int bf_ct_validate_hook_compat(const struct bf_chain *chain)
{
    assert(chain);

    if (chain->hook != BF_HOOK_XDP)
        return 0;

    if (!(chain->flags & BF_FLAG(BF_CHAIN_CONNTRACK)))
        return 0;

    return bf_err_r(
        -ENOTSUP,
        "chain '%s': rules containing ct.conntrack (or any rule with an "
        "implicit ACCEPT that creates conntrack entries) cannot be attached "
        "to BF_HOOK_XDP. XDP has no egress hook; outbound-initiated flows "
        "can never be tracked. Use TC attachment "
        "(BF_HOOK_TC_INGRESS / BF_HOOK_TC_EGRESS) for stateful rules, or "
        "mark rules NOTRACK to suppress entry creation and use XDP",
        chain->name);
}

void bf_ct_warn_chain_policy(const struct bf_chain *chain)
{
    bool has_new_accept = false;
    bool has_established_fastpath = false;
    bool has_accept_without_notrack = false;

    assert(chain);

    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->disabled)
            continue;

        if (rule->verdict == BF_VERDICT_ACCEPT && !bf_rule_has_notrack(rule))
            has_accept_without_notrack = true;

        if (!_bf_ct_rule_has_ct_matcher(rule))
            continue;

        if (rule->verdict == BF_VERDICT_ACCEPT &&
            _bf_ct_rule_matches_ct_state(rule, CT_STATE_NEW))
            has_new_accept = true;

        if (rule->verdict == BF_VERDICT_ACCEPT &&
            (_bf_ct_rule_matches_ct_state(rule, CT_STATE_ESTABLISHED) ||
             _bf_ct_rule_matches_ct_state(rule, CT_STATE_RELATED)))
            has_established_fastpath = true;
    }

    if ((chain->flags & BF_FLAG(BF_CHAIN_CONNTRACK)) && has_new_accept &&
        !has_established_fastpath) {
        bf_warn(
            "chain '%s' has conntrack NEW rules but no ESTABLISHED or "
            "RELATED rule. Return traffic will re-evaluate the full chain "
            "on every packet. Add: match { ctstate: ESTABLISHED|RELATED } "
            "-> ACCEPT at the top of the chain",
            chain->name);
    }

    if (chain->policy == BF_VERDICT_ACCEPT &&
        !_bf_ct_chain_has_ct_matcher(chain)) {
        bf_warn(
            "chain '%s' policy is ACCEPT but no ct.conntrack rules are "
            "defined. No conntrack entries are consulted; adding an "
            "ESTABLISHED fast-path later will not match existing flows",
            chain->name);
    }

    if (_bf_ct_chain_has_ct_matcher(chain) && !has_accept_without_notrack &&
        chain->policy != BF_VERDICT_ACCEPT) {
        bf_warn(
            "chain '%s' has ct.conntrack rules but every ACCEPT rule is "
            "marked NOTRACK and policy is not ACCEPT. No conntrack entries "
            "will be created; ESTABLISHED rules will never match",
            chain->name);
    }
}

int bf_ct_parse_mem_available_kb(const char *meminfo, uint64_t *out_kb)
{
    const char *line;
    unsigned long kb;

    assert(meminfo);
    assert(out_kb);

    line = meminfo;
    while (*line) {
        const char *end = strchr(line, '\n');

        if (!strncmp(line, "MemAvailable:", 13)) {
            if (sscanf(line + 13, "%lu", &kb) != 1)
                return -EINVAL;
            *out_kb = kb;
            return 0;
        }

        if (!end)
            break;
        line = end + 1;
    }

    return -ENOENT;
}

static int _bf_ct_read_mem_available_kb(uint64_t *out_kb)
{
    FILE *f;
    char buf[4096];
    size_t nread;
    int r;

    assert(out_kb);

    f = fopen("/proc/meminfo", "re");
    if (!f)
        return -errno;

    nread = fread(buf, 1, sizeof(buf) - 1, f);
    if (ferror(f)) {
        r = -EIO;
        goto out;
    }
    if (!nread) {
        r = -EIO;
        goto out;
    }

    buf[nread] = '\0';
    r = bf_ct_parse_mem_available_kb(buf, out_kb);

out:
    fclose(f);
    return r;
}

uint64_t bf_ct_estimate_map_bytes(const struct bf_ct_maps_opts *opts)
{
    uint32_t max_tcp = BF_CT_MAP_TCP_MAX;
    uint32_t max_tcp6 = BF_CT_MAP_TCP6_MAX;
    uint32_t max_any = BF_CT_MAP_ANY_MAX;
    uint32_t max_any6 = BF_CT_MAP_ANY6_MAX;
    uint32_t max_src_rate = BF_CT_SRC_RATE_MAX;
    uint32_t max_src_count = BF_CT_SRC_COUNT_MAX;
    uint32_t max_spi_reverse = BF_CT_MAP_SPI_REVERSE_MAX;
    uint64_t flow_bytes;
    uint64_t side_bytes;

    if (opts) {
        max_tcp = _bf_ct_opt_or_default(opts->max_tcp, max_tcp);
        max_tcp6 = _bf_ct_opt_or_default(opts->max_tcp6, max_tcp6);
        max_any = _bf_ct_opt_or_default(opts->max_any, max_any);
        max_any6 = _bf_ct_opt_or_default(opts->max_any6, max_any6);
        max_src_rate = _bf_ct_opt_or_default(opts->max_src_rate, max_src_rate);
        max_src_count =
            _bf_ct_opt_or_default(opts->max_src_count, max_src_count);
        max_spi_reverse =
            _bf_ct_opt_or_default(opts->max_spi_reverse, max_spi_reverse);
    }

    flow_bytes = (uint64_t)(max_tcp + max_tcp6 + max_any + max_any6) *
                 sizeof(struct ct_entry);
    side_bytes = (uint64_t)max_src_rate * sizeof(struct ct_rate_entry) +
                 (uint64_t)max_src_count * sizeof(struct ct_src_count_entry) +
                 (uint64_t)max_spi_reverse * sizeof(__u32);

    return flow_bytes + side_bytes;
}

void bf_ct_warn_map_memory(const struct bf_ct_maps_opts *opts)
{
    uint32_t max_tcp = BF_CT_MAP_TCP_MAX;
    uint32_t max_tcp6 = BF_CT_MAP_TCP6_MAX;
    uint32_t max_any = BF_CT_MAP_ANY_MAX;
    uint32_t max_any6 = BF_CT_MAP_ANY6_MAX;
    uint64_t total_bytes;
    uint64_t mem_kb = 0;
    int r;

    if (opts) {
        max_tcp = _bf_ct_opt_or_default(opts->max_tcp, max_tcp);
        max_tcp6 = _bf_ct_opt_or_default(opts->max_tcp6, max_tcp6);
        max_any = _bf_ct_opt_or_default(opts->max_any, max_any);
        max_any6 = _bf_ct_opt_or_default(opts->max_any6, max_any6);
    }

    if (max_tcp < _BF_CT_MAP_MIN_ENTRIES ||
        max_tcp6 < _BF_CT_MAP_MIN_ENTRIES ||
        max_any < _BF_CT_MAP_MIN_ENTRIES ||
        max_any6 < _BF_CT_MAP_MIN_ENTRIES) {
        bf_warn("ct_map max_entries is very small on at least one flow map. "
                "LRU eviction may disrupt established connections");
    }

    total_bytes = bf_ct_estimate_map_bytes(opts);

    r = _bf_ct_read_mem_available_kb(&mem_kb);
    if (r)
        return;

    if (total_bytes >
        mem_kb * 1024ULL * _BF_CT_MEM_FRACTION_NUM / _BF_CT_MEM_FRACTION_DEN) {
        bf_warn(
            "ct_map size (%llu MB) exceeds 25%% of available memory "
            "(%llu MB). Consider reducing max_entries",
            (unsigned long long)(total_bytes / (1024ULL * 1024ULL)),
            (unsigned long long)(mem_kb / 1024ULL));
    }
}

void bf_ct_timeouts_clamp(struct ct_timeouts *timeouts)
{
    assert(timeouts);

    for (size_t i = 0; i < ARRAY_SIZE(_bf_ct_timeout_bounds); ++i) {
        const struct _bf_ct_timeout_bound *bound = &_bf_ct_timeout_bounds[i];
        __u64 *field = (__u64 *)((uint8_t *)timeouts + bound->offset);
        __u64 old = *field;
        __u64 clamped = old;

        if (clamped < bound->min_ns)
            clamped = bound->min_ns;
        if (clamped > bound->max_ns)
            clamped = bound->max_ns;

        if (clamped != old) {
            bf_warn("ct timeout %s clamped from %llu to %llu ns", bound->name,
                    (unsigned long long)old, (unsigned long long)clamped);
            *field = clamped;
        }
    }
}
