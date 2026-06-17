/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BF_CT_BPF_WITH_LIBBPF_HELPERS
#define BF_CT_BPF_HARNESS

#include <bpfilter/ct.h>

#include "cgen/runtime.h"
#include "ct/bpf/create.h"
#include "ct/bpf/lookup.h"
#include "ct/bpf/parse.h"
#include "ct/bpf/state.h"

#define CT_TEST_MAP_MAX 4096u

struct ct_test_ctrl
{
    __u8 op;
    __u8 pad[7];
};

#define CT_TEST_OP_LOOKUP 0
#define CT_TEST_OP_LOOKUP_CREATE 1
#define CT_TEST_OP_LOOKUP_UPDATE_TCP 2

struct ct_test_runtime_val
{
    __u8 data[512];
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ct_test_runtime_val);
} ct_test_runtime SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ct_test_ctrl);
} ct_test_ctrl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_key_v4);
    __type(value, struct ct_entry);
} ct_map_tcp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_key_v6);
    __type(value, struct ct_entry);
} ct_map_tcp6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_key_v4);
    __type(value, struct ct_entry);
} ct_map_any SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_key_v6);
    __type(value, struct ct_entry);
} ct_map_any6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_ip_key);
    __type(value, struct ct_rate_entry);
} ct_src_rate SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_ip_key);
    __type(value, struct ct_src_count_entry);
} ct_src_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_TEST_MAP_MAX);
    __type(key, struct ct_spi_reverse_key);
    __type(value, __u32);
} ct_spi_reverse SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ct_stats_counters);
} ct_stats SEC(".maps");

static __always_inline int
_ct_harness_load_l4(struct __sk_buff *skb, struct bf_runtime *ctx, __u32 l4_off)
{
    int r;

    if (skb->len >= l4_off + sizeof(ctx->scratch)) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->scratch,
                               sizeof(ctx->scratch));
        if (r)
            return r;
        ctx->l4_size = sizeof(ctx->scratch);
        return 0;
    }

    if (skb->len >= l4_off + 48) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->scratch, 48);
        if (r)
            return r;
        ctx->l4_size = 48;
        return 0;
    }

    if (skb->len >= l4_off + BF_L4_SLICE_LEN) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->l4, BF_L4_SLICE_LEN);
        if (r)
            return r;
        ctx->l4_size = BF_L4_SLICE_LEN;
        return 0;
    }

    if (skb->len >= l4_off + 20) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->l4, 20);
        if (r)
            return r;
        ctx->l4_size = 20;
        return 0;
    }

    if (skb->len >= l4_off + 16) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->l4, 16);
        if (r)
            return r;
        ctx->l4_size = 16;
        return 0;
    }

    if (skb->len >= l4_off + 8) {
        r = bpf_skb_load_bytes(skb, l4_off, ctx->l4, 8);
        if (r)
            return r;
        ctx->l4_size = 8;
        return 0;
    }

    return -1;
}

static __always_inline int
_ct_harness_fill_runtime(struct __sk_buff *skb, struct bf_runtime *ctx)
{
    struct ethhdr eth = {};
    struct iphdr *ip4;
    struct ipv6hdr *ip6;
    __u32 l3_off = sizeof(eth);
    __u32 l4_off;
    __u32 ihl;
    int r;

    r = bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    if (r)
        return r;

    if (eth.h_proto == bpf_htons(ETH_P_IP)) {
        r = bpf_skb_load_bytes(skb, l3_off, ctx->l3, sizeof(struct iphdr));
        if (r)
            return r;

        ip4 = (struct iphdr *)ctx->l3;
        ihl = ip4->ihl * 4;
        if (ihl < 20 || ihl > BF_L3_SLICE_LEN)
            return -1;

        r = bpf_skb_load_bytes(skb, l3_off, ctx->l3, ihl);
        if (r)
            return r;

        l4_off = l3_off + ihl;
        r = _ct_harness_load_l4(skb, ctx, l4_off);
        if (r)
            return r;

        ctx->arg = skb;
        ctx->pkt_size = skb->len;
        ctx->l3_offset = l3_off;
        ctx->l4_offset = l4_off;
        ctx->l3_size = ihl;

        return 0;
    }

    if (eth.h_proto != bpf_htons(ETH_P_IPV6))
        return -1;

    r = bpf_skb_load_bytes(skb, l3_off, ctx->l3, sizeof(struct ipv6hdr));
    if (r)
        return r;

    ip6 = (struct ipv6hdr *)ctx->l3;
    l4_off = l3_off + sizeof(*ip6);
    r = _ct_harness_load_l4(skb, ctx, l4_off);
    if (r)
        return r;

    ctx->arg = skb;
    ctx->pkt_size = skb->len;
    ctx->l3_offset = l3_off;
    ctx->l4_offset = l4_off;
    ctx->l3_size = sizeof(*ip6);

    return 0;
}

SEC("tc")
int ct_harness(struct __sk_buff *skb)
{
    struct ct_test_ctrl *ctrl;
    struct bf_ct_bpf_maps maps = {
        .tcp = &ct_map_tcp,
        .tcp6 = &ct_map_tcp6,
        .any = &ct_map_any,
        .any6 = &ct_map_any6,
        .src_rate = &ct_src_rate,
        .src_count = &ct_src_count,
        .spi_reverse = &ct_spi_reverse,
        .stats = &ct_stats,
    };
    struct ct_key_v4 key_v4 = {};
    struct ct_key_v6 key_v6 = {};
    struct ct_entry *entry;
    void *flow_map;
    __u32 ctrl_key = 0;
    __u8 is_reply = 0;
    __u8 state;
    __u8 is_v6 = 0;
    struct bf_ct_pkt_info pkt = {};
    struct bf_runtime *ctx;
    struct ct_test_runtime_val *storage;

    ctrl = bpf_map_lookup_elem(&ct_test_ctrl, &ctrl_key);
    if (!ctrl)
        return TC_ACT_UNSPEC;

    storage = bpf_map_lookup_elem(&ct_test_runtime, &ctrl_key);
    if (!storage)
        return TC_ACT_UNSPEC;

    ctx = (struct bf_runtime *)storage->data;
    __builtin_memset(ctx, 0, sizeof(*ctx));

    if (_ct_harness_fill_runtime(skb, ctx))
        return TC_ACT_UNSPEC;

    state = bf_ct_bpf_lookup(ctx, &maps, &key_v4, &key_v6, &is_reply);
    is_v6 = key_v6.proto != 0;

    if (ctrl->op >= CT_TEST_OP_LOOKUP_UPDATE_TCP &&
        bf_ct_bpf_parse_runtime(ctx, &pkt) == 0) {
        flow_map = bf_ct_bpf_flow_map(&maps, is_v6, pkt.proto);
        entry = is_v6 ? bpf_map_lookup_elem(flow_map, &key_v6)
                      : bpf_map_lookup_elem(flow_map, &key_v4);
        if (entry) {
            if (pkt.tcp)
                bf_ct_bpf_tcp_fsm(entry, pkt.tcp, is_reply);
            else if (pkt.proto == IPPROTO_SCTP)
                bf_ct_bpf_sctp_fsm(entry, pkt.sctp_chunk, is_reply);
            state = bf_ct_entry_to_rule_state(entry, is_reply);
        }
    }

    if (ctrl->op >= CT_TEST_OP_LOOKUP_CREATE)
        bf_ct_bpf_create_if_new(ctx, &maps, state, is_v6, &key_v4, &key_v6);

    return state;
}

char _license[] SEC("license") = "GPL";
