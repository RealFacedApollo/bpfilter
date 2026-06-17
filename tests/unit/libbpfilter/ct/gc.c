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

static void _bft_require_bpffs(void)
{
    if (access("/sys/fs/bpf", F_OK) != 0)
        skip();
}

static int _bft_setup_ctx_bpffs_ct(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    int r;

    _bft_require_bpffs();

    assert_ok(bft_tmpdir_new(&tmpdir));
    *state = TAKE_PTR(tmpdir);

    bf_ctx_teardown();
    r = bf_ctx_setup_ex(false, "/sys/fs/bpf", 0, BF_CTX_F_CONNTRACK);
    if (r)
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
        cmocka_unit_test_setup_teardown(gc_heartbeat_updates_meta,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
