// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/ctx.h>
#include <bpfilter/ct.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>

#include <bpf/libbpf.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cgen/fixup.h"
#include "cgen/handle.h"
#include "cgen/program.h"
#include "core/lock.h"
#include "test.h"

#define _BFT_CT_SPLIT_FILLER_RULES 288u

static int _bft_split_chain_new(struct bf_chain **chain)
{
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    struct bf_match_ct_payload established = {
        .state_mask = CT_STATE_ESTABLISHED | CT_STATE_RELATED,
    };
    uint16_t accept_port = htobe16(443);
    size_t i;

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                  &established, sizeof(established), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    for (i = 0; i < _BFT_CT_SPLIT_FILLER_RULES; ++i) {
        uint16_t dport = htobe16((uint16_t)(10000 + i));

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                      &dport, sizeof(dport), false));
        rule->verdict = BF_VERDICT_DROP;
        assert_ok(bf_list_add_tail(&rules, rule));
    }

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                  &accept_port, sizeof(accept_port), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    return bf_chain_new(chain, "ct_split", BF_HOOK_TC_INGRESS, BF_VERDICT_DROP,
                        NULL, &rules);
}

static __be32 _ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    __be32 val;
    uint8_t *p = (uint8_t *)&val;

    p[0] = a;
    p[1] = b;
    p[2] = c;
    p[3] = d;

    return val;
}

static void _bft_require_linux(void)
{
    if (access("/sys/fs/bpf", F_OK) != 0)
        skip();
}

static void _bft_skip_without_bpf(int r)
{
    if (r == -EPERM || r == -EACCES)
        skip();
}

static void _bft_skip_load_without_bpf(struct bf_chain **chain,
                                       struct bf_handle **handle,
                                       struct bf_program **program, int r)
{
    if (r == -EPERM || r == -EACCES) {
        bf_program_free(program);
        bf_handle_free(handle);
        bf_chain_free(chain);
        skip();
    }
}

static bool _bft_ct_has_prog_array_fixup(const struct bf_program *program)
{
    bf_list_node *node;

    bf_list_foreach (&program->fixups, node) {
        struct bf_fixup *fixup = bf_list_node_get_data(node);

        if (fixup->type == BF_FIXUP_TYPE_PROG_ARRAY_FD)
            return true;
    }

    return false;
}

static void _bft_ctx_setup_ct_or_skip(void)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    int r;

    _bft_require_linux();
    bf_ctx_teardown();
    r = bf_ctx_setup_ex(false, "/sys/fs/bpf", 0, BF_CTX_F_CONNTRACK);
    _bft_skip_without_bpf(r);

    // Conntrack maps are created lazily; arm them so codegen emits the
    // conntrack datapath and the load tests find a populated map set.
    if (bf_lock_init(&lock, BF_LOCK_WRITE))
        skip();
    _bft_skip_without_bpf(bf_ctx_ensure_ct_maps(lock.pindir_fd));
}

static int _bft_example_chain(struct bf_chain **chain)
{
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    struct bf_match_ct_payload established = {
        .state_mask = CT_STATE_ESTABLISHED | CT_STATE_RELATED,
    };
    uint16_t dport = htobe16(443);

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                  &established, sizeof(established), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                  &dport, sizeof(dport), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    return bf_chain_new(chain, "ct_example", BF_HOOK_TC_INGRESS,
                        BF_VERDICT_DROP, NULL, &rules);
}

static size_t _bft_tcp_syn(uint8_t *buf, size_t cap, __be32 saddr, __be32 daddr,
                           __be16 sport, __be16 dport)
{
    struct ethhdr *eth = (struct ethhdr *)buf;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    size_t len = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);

    if (cap < len)
        return 0;

    memset(buf, 0, len);
    eth->h_proto = htobe16(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htobe16((uint16_t)(sizeof(*ip) + sizeof(*tcp)));
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    tcp->source = sport;
    tcp->dest = dport;
    tcp->syn = 1;
    tcp->doff = 5;

    return len;
}

static size_t _bft_tcp_ack(uint8_t *buf, size_t cap, __be32 saddr, __be32 daddr,
                           __be16 sport, __be16 dport)
{
    struct ethhdr *eth = (struct ethhdr *)buf;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    size_t len = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);

    if (cap < len)
        return 0;

    memset(buf, 0, len);
    eth->h_proto = htobe16(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htobe16((uint16_t)(sizeof(*ip) + sizeof(*tcp)));
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    tcp->source = sport;
    tcp->dest = dport;
    tcp->ack = 1;
    tcp->doff = 5;

    return len;
}

static int _bft_ct_stats_sum(struct ct_stats_counters *out)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    int ncpu = libbpf_num_possible_cpus();
    __u32 key = 0;
    struct ct_stats_counters *percpu;
    int stats_fd;
    int r;
    int i;

    if (!maps || ncpu <= 0)
        return -EINVAL;

    stats_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_STATS);
    if (stats_fd < 0)
        return stats_fd;

    percpu = calloc((size_t)ncpu, sizeof(*percpu));
    if (!percpu)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(stats_fd, &key, percpu);
    if (r) {
        free(percpu);
        return r;
    }

    memset(out, 0, sizeof(*out));
    for (i = 0; i < ncpu; ++i) {
        out->new_tcp += percpu[i].new_tcp;
        out->established += percpu[i].established;
    }

    free(percpu);
    return 0;
}

static int _bft_ct_tests_teardown(void **state)
{
    (void)state;
    bf_ctx_teardown();

    return 0;
}

static void example_chain_syn_ack_stats(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;
    struct ct_stats_counters stats = {};
    uint8_t pkt[128];
    size_t pkt_len;
    __be32 saddr = _ipv4(10, 0, 0, 1);
    __be32 daddr = _ipv4(10, 0, 0, 2);
    __be16 sport = htobe16(1234);
    __be16 dport = htobe16(443);
    int r;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_example_chain(&chain));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));
    r = bf_program_load(program);
    _bft_skip_load_without_bpf(&chain, &handle, &program, r);
    assert_ok(r);

    pkt_len = _bft_tcp_syn(pkt, sizeof(pkt), saddr, daddr, sport, dport);
    assert_true(pkt_len > 0);

    r = bf_bpf_prog_run(handle->prog_fd, pkt, pkt_len, NULL, 0);
    assert_int_equal(r, TCX_PASS);

    assert_ok(_bft_ct_stats_sum(&stats));
    assert_int_equal(stats.new_tcp, 1);

    pkt_len = _bft_tcp_ack(pkt, sizeof(pkt), saddr, daddr, sport, dport);
    assert_true(pkt_len > 0);

    r = bf_bpf_prog_run(handle->prog_fd, pkt, pkt_len, NULL, 0);
    assert_int_equal(r, TCX_PASS);

    memset(&stats, 0, sizeof(stats));
    assert_ok(_bft_ct_stats_sum(&stats));
    assert_int_equal(stats.new_tcp, 1);
    assert_true(stats.established >= 1);
}

static void example_chain_prog_run(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;
    uint8_t pkt[128];
    size_t pkt_len;
    int r;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_example_chain(&chain));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));
    r = bf_program_load(program);
    _bft_skip_load_without_bpf(&chain, &handle, &program, r);
    assert_ok(r);

    pkt_len = _bft_tcp_syn(pkt, sizeof(pkt), _ipv4(10, 0, 0, 1),
                           _ipv4(10, 0, 0, 2), htobe16(1234),
                           htobe16(443));
    assert_true(pkt_len > 0);

    r = bf_bpf_prog_run(handle->prog_fd, pkt, pkt_len, NULL, 0);
    assert_int_equal(r, TCX_PASS);
}

static void split_chain_generates_segments(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_split_chain_new(&chain));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));

    assert_true(program->handle->n_segments > 1);
    assert_true(_bft_ct_has_prog_array_fixup(program));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(split_chain_generates_segments),
        cmocka_unit_test(example_chain_prog_run),
        cmocka_unit_test(example_chain_syn_ack_stats),
    };

    return cmocka_run_group_tests(tests, NULL, _bft_ct_tests_teardown);
}
