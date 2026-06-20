// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <bpf/libbpf.h>
#include <errno.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/ct.h>
#include <bpfilter/ctx.h>

#include "core/lock.h"
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

static struct in6_addr _in6(uint8_t last)
{
    struct in6_addr addr = {};

    addr.s6_addr[0] = 0x20;
    addr.s6_addr[1] = 0x01;
    addr.s6_addr[15] = last;

    return addr;
}

static void _bft_require_bpffs(void)
{
    if (access("/sys/fs/bpf", F_OK) != 0)
        skip();
}

static int _bft_setup_ctx_bpffs_ct(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    int r;

    _bft_require_bpffs();

    assert_ok(bft_tmpdir_new(&tmpdir));
    *state = TAKE_PTR(tmpdir);

    bf_ctx_teardown();
    r = bf_ctx_setup_ex(false, "/sys/fs/bpf", 0, BF_CTX_F_CONNTRACK);
    if (r)
        skip();

    // Conntrack maps are created lazily; arm them so the GC tests operate on a
    // populated map set.
    if (bf_lock_init(&lock, BF_LOCK_WRITE))
        skip();
    if (bf_ctx_ensure_ct_maps(lock.pindir_fd))
        skip();

    return 0;
}

static int _bft_teardown_ctx_bpffs(void **state)
{
    struct bft_tmpdir *tmpdir = *state;

    bf_ctx_teardown();
    bft_tmpdir_free(&tmpdir);
    *state = NULL;

    return 0;
}

static int _bft_ct_stats_sum(const struct bf_ct_maps *maps,
                             struct ct_stats_counters *out)
{
    int ncpu = libbpf_num_possible_cpus();
    __u32 key = 0;
    struct ct_stats_counters *percpu;
    int stats_fd;
    int r;
    int i;

    stats_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_STATS);
    if (stats_fd < 0)
        return stats_fd;

    if (ncpu <= 0)
        return -EINVAL;

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
        out->gc_phase1_marked += percpu[i].gc_phase1_marked;
        out->gc_phase2_deleted += percpu[i].gc_phase2_deleted;
    }

    free(percpu);
    return 0;
}

static void gc_two_phase_eviction(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_key_v4 key = {
        .lo_ip = _be32(10, 0, 0, 1),
        .hi_ip = _be32(10, 0, 0, 2),
        .discriminator = (443u << 16) | 55000u,
        .proto = IPPROTO_TCP,
    };
    struct ct_entry entry = {
        .proto = IPPROTO_TCP,
        .orig_lo_is_src = 1,
        .orig_src_ip = _be32(10, 0, 0, 1),
        .orig_dst_ip = _be32(10, 0, 0, 2),
    };
    struct ct_timeouts timeouts;
    struct ct_ip_key ip_key;
    struct ct_src_count_entry count = {.count = 1};
    struct ct_stats_counters stats_before = {};
    struct ct_stats_counters stats_after = {};
    struct bf_ct_gc gc;
    struct bf_ct_gc_opts opts = {.batch_size = 100};
    __u32 tkey = 0;
    __u64 now_ns;
    int tcp_fd;
    int timeouts_fd;
    int src_count_fd;
    int r;

    (void)state;

    assert_non_null(maps);

    tcp_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP);
    timeouts_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TIMEOUTS);
    src_count_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SRC_COUNT);
    assert_int_gte(tcp_fd, 0);
    assert_int_gte(timeouts_fd, 0);
    assert_int_gte(src_count_fd, 0);

    bf_ct_timeouts_defaults(&timeouts);
    timeouts.tcp_syn_ns = 1ULL * BF_CT_NS_PER_S;
    r = bf_bpf_map_update_elem(timeouts_fd, &tkey, &timeouts, BPF_ANY);
    assert_ok(r);

    now_ns = 3ULL * BF_CT_NS_PER_S;
    entry.last_seen_ns = now_ns - (2ULL * BF_CT_NS_PER_S);
    entry.created_ns = entry.last_seen_ns;

    r = bf_bpf_map_update_elem(tcp_fd, &key, &entry, BPF_ANY);
    assert_ok(r);

    bf_ct_ip_key_from_v4(entry.orig_src_ip, &ip_key);
    r = bf_bpf_map_update_elem(src_count_fd, &ip_key, &count, BPF_ANY);
    assert_ok(r);

    assert_ok(_bft_ct_stats_sum(maps, &stats_before));

    bf_ct_gc_init(&gc);
    assert_ok(bf_ct_gc_sweep_batch(maps, &gc, &opts));

    r = bf_bpf_map_lookup_elem(tcp_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_DYING);

    assert_ok(_bft_ct_stats_sum(maps, &stats_after));
    assert_true(stats_after.gc_phase1_marked >=
                stats_before.gc_phase1_marked + 1);

    assert_ok(bf_ct_gc_sweep_batch(maps, &gc, &opts));

    r = bf_bpf_map_lookup_elem(tcp_fd, &key, &entry);
    assert_int_equal(r, -ENOENT);

    r = bf_bpf_map_lookup_elem(src_count_fd, &ip_key, &count);
    assert_int_equal(r, -ENOENT);

    stats_before = stats_after;
    assert_ok(_bft_ct_stats_sum(maps, &stats_after));
    assert_true(stats_after.gc_phase2_deleted >=
                stats_before.gc_phase2_deleted + 1);
}

/* Reaping a dying IPv6 entry must decrement the per-source count. The source is
 * reconstructed from the flow key (orig_src_ip only holds 4 bytes of a v6
 * address), so a v4-keyed decrement would miss the entry entirely. */
static void gc_v6_src_count_decrement(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_key_v6 key = {
        .lo_ip = _in6(1),
        .hi_ip = _in6(2),
        .discriminator = (443u << 16) | 55000u,
        .proto = IPPROTO_TCP,
    };
    struct ct_entry entry = {
        .proto = IPPROTO_TCP,
        .flags = CT_FLAG_DYING,
        .orig_lo_is_src = 1,
    };
    struct ct_ip_key ip_key;
    struct ct_src_count_entry count = {.count = 1};
    struct bf_ct_gc gc;
    struct bf_ct_gc_opts opts = {.batch_size = 100};
    int tcp6_fd;
    int src_count_fd;
    int r;

    (void)state;

    assert_non_null(maps);

    tcp6_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP6);
    src_count_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SRC_COUNT);
    assert_int_gte(tcp6_fd, 0);
    assert_int_gte(src_count_fd, 0);

    r = bf_bpf_map_update_elem(tcp6_fd, &key, &entry, BPF_ANY);
    assert_ok(r);

    /* The source is key.lo_ip because orig_lo_is_src is set. */
    bf_ct_ip_key_from_v6(&key.lo_ip, &ip_key);
    r = bf_bpf_map_update_elem(src_count_fd, &ip_key, &count, BPF_ANY);
    assert_ok(r);

    bf_ct_gc_init(&gc);
    assert_ok(bf_ct_gc_sweep_batch(maps, &gc, &opts));

    r = bf_bpf_map_lookup_elem(tcp6_fd, &key, &entry);
    assert_int_equal(r, -ENOENT);

    /* count dropped from 1 to 0, so the entry is removed. */
    r = bf_bpf_map_lookup_elem(src_count_fd, &ip_key, &count);
    assert_int_equal(r, -ENOENT);
}

/* Reconciliation rebuilds src_count from the live flow entries: an inflated
 * count is corrected down to the true number of connections, and a source with
 * no live entry is pruned. Covers both an IPv4 and an IPv6 source. */
static void gc_reconcile_rebuilds_src_count(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_key_v4 k4a = {
        .lo_ip = _be32(10, 0, 0, 1),
        .hi_ip = _be32(10, 0, 0, 9),
        .discriminator = (80u << 16) | 40000u,
        .proto = IPPROTO_TCP,
    };
    struct ct_key_v4 k4b = {
        .lo_ip = _be32(10, 0, 0, 1),
        .hi_ip = _be32(10, 0, 0, 9),
        .discriminator = (80u << 16) | 40001u,
        .proto = IPPROTO_TCP,
    };
    struct ct_key_v6 k6 = {
        .lo_ip = _in6(1),
        .hi_ip = _in6(2),
        .discriminator = (443u << 16) | 55000u,
        .proto = IPPROTO_TCP,
    };
    struct ct_entry entry = {.proto = IPPROTO_TCP, .orig_lo_is_src = 1};
    struct ct_ip_key ip_v4;
    struct ct_ip_key ip_v6;
    struct ct_ip_key ip_stale;
    struct ct_src_count_entry count;
    int tcp_fd;
    int tcp6_fd;
    int src_count_fd;
    int r;

    (void)state;

    assert_non_null(maps);

    tcp_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP);
    tcp6_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP6);
    src_count_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SRC_COUNT);
    assert_int_gte(tcp_fd, 0);
    assert_int_gte(tcp6_fd, 0);
    assert_int_gte(src_count_fd, 0);

    /* Two live v4 connections share source 10.0.0.1; one live v6 connection. */
    assert_ok(bf_bpf_map_update_elem(tcp_fd, &k4a, &entry, BPF_ANY));
    assert_ok(bf_bpf_map_update_elem(tcp_fd, &k4b, &entry, BPF_ANY));
    assert_ok(bf_bpf_map_update_elem(tcp6_fd, &k6, &entry, BPF_ANY));

    bf_ct_ip_key_from_v4(k4a.lo_ip, &ip_v4);
    bf_ct_ip_key_from_v6(&k6.lo_ip, &ip_v6);
    bf_ct_ip_key_from_v4(_be32(192, 168, 0, 5), &ip_stale);

    /* Drift: v4 inflated to 5, v6 inflated to 3, plus a stale source with no
     * live entry. */
    count.count = 5;
    count._pad = 0;
    assert_ok(bf_bpf_map_update_elem(src_count_fd, &ip_v4, &count, BPF_ANY));
    count.count = 3;
    assert_ok(bf_bpf_map_update_elem(src_count_fd, &ip_v6, &count, BPF_ANY));
    count.count = 7;
    assert_ok(bf_bpf_map_update_elem(src_count_fd, &ip_stale, &count, BPF_ANY));

    assert_ok(bf_ct_gc_reconcile_src_count(maps));

    assert_ok(bf_bpf_map_lookup_elem(src_count_fd, &ip_v4, &count));
    assert_int_equal(count.count, 2);

    assert_ok(bf_bpf_map_lookup_elem(src_count_fd, &ip_v6, &count));
    assert_int_equal(count.count, 1);

    r = bf_bpf_map_lookup_elem(src_count_fd, &ip_stale, &count);
    assert_int_equal(r, -ENOENT);
}

static void gc_heartbeat_updates_meta(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_meta meta = {};
    struct bf_ct_gc gc;
    struct bf_ct_gc_opts opts = {.batch_size = 100};

    (void)state;

    assert_non_null(maps);

    bf_ct_gc_init(&gc);
    assert_ok(bf_ct_gc_sweep_batch(maps, &gc, &opts));
    assert_ok(bf_ct_meta_get(&meta, maps));
    assert_true(meta.last_sweep_ns > 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(gc_two_phase_eviction,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(gc_v6_src_count_decrement,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(gc_reconcile_rebuilds_src_count,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(gc_heartbeat_updates_meta,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
