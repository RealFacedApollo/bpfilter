// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/bpf.h>
#include <bpfilter/ct.h>
#include <bpfilter/ctx.h>

#include <linux/bpf.h>

#include <errno.h>
#include <unistd.h>

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

    // Conntrack maps are created lazily; arm them so the BPF round-trip tests
    // find a populated map set via bf_ctx_get_ct_maps().
    if (bf_lock_init(&lock, BF_LOCK_WRITE))
        skip();
    if (bf_ctx_ensure_ct_maps(lock.pindir_fd))
        skip();

    return 0;
}

static int _bft_setup_ctx_bpffs(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    int r;

    _bft_require_bpffs();

    assert_ok(bft_tmpdir_new(&tmpdir));
    *state = TAKE_PTR(tmpdir);

    bf_ctx_teardown();
    r = bf_ctx_setup(false, "/sys/fs/bpf", 0);
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

static void maps_bpf_entry_roundtrip(void **state)
{
    struct bf_ct_maps *ct_maps;
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    struct ct_entry out = {};
    struct ct_timeouts timeouts = {};
    __u32 tkey = 0;
    int map_fd;
    int r;

    (void)state;

    ct_maps = bf_ctx_get_ct_maps();
    assert_non_null(ct_maps);

    map_fd = bf_ct_maps_get_fd(ct_maps, BF_CT_MAP_TCP);
    assert_int_gt(map_fd, 0);

    key.lo_ip = _be32(192, 0, 2, 1);
    key.hi_ip = _be32(192, 0, 2, 2);
    key.discriminator = (443u << 16) | 55000u;
    key.proto = IPPROTO_TCP;

    entry.proto = IPPROTO_TCP;
    entry.orig_lo_is_src = 1;
    entry.orig_discriminator = (443u << 16) | 55000u;
    entry.created_ns = 42;
    entry.last_seen_ns = 42;

    r = bf_bpf_map_update_elem(map_fd, &key, &entry, BPF_ANY);
    assert_ok(r);

    r = bf_bpf_map_lookup_elem(map_fd, &key, &out);
    assert_ok(r);

    assert_int_equal(out.proto, IPPROTO_TCP);
    assert_int_equal(out.orig_lo_is_src, 1);
    assert_int_equal(out.orig_discriminator, entry.orig_discriminator);
    assert_int_equal(out.created_ns, 42);

    map_fd = bf_ct_maps_get_fd(ct_maps, BF_CT_MAP_TIMEOUTS);
    assert_int_gt(map_fd, 0);

    r = bf_bpf_map_lookup_elem(map_fd, &tkey, &timeouts);
    assert_ok(r);

    assert_int_equal(timeouts.tcp_syn_ns, 30ULL * BF_CT_NS_PER_S);
    assert_int_equal(timeouts.tcp_established_ns, 6ULL * 3600ULL * BF_CT_NS_PER_S);
}

static void maps_bpf_reopen_pinned(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_ct_maps_ struct bf_ct_maps *maps = NULL;
    struct bf_ct_maps_opts opts = {
        .max_tcp = 64,
        .max_tcp6 = 64,
        .max_any = 64,
        .max_any6 = 64,
        .max_src_rate = 64,
        .max_src_count = 64,
    };
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    struct ct_entry out = {};
    int map_fd;
    int r;

    (void)state;

    assert_ok(bf_lock_init(&lock, BF_LOCK_WRITE));

    assert_ok(bf_ct_maps_init(&maps, lock.pindir_fd, &opts));

    map_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP);
    assert_int_gt(map_fd, 0);

    key.lo_ip = _be32(10, 1, 2, 3);
    key.hi_ip = _be32(10, 1, 2, 4);
    key.discriminator = (8080u << 16) | 9090u;
    key.proto = IPPROTO_TCP;

    entry.proto = IPPROTO_TCP;
    entry.orig_lo_is_src = 1;
    entry.orig_discriminator = key.discriminator;

    assert_ok(bf_bpf_map_update_elem(map_fd, &key, &entry, BPF_ANY));

    bf_ct_maps_free(&maps);

    assert_ok(bf_ct_maps_open(&maps, lock.pindir_fd));

    map_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TCP);
    assert_int_gt(map_fd, 0);

    r = bf_bpf_map_lookup_elem(map_fd, &key, &out);
    assert_ok(r);
    assert_int_equal(out.orig_discriminator, key.discriminator);
}

static void maps_bpf_spi_reverse_roundtrip(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    _free_bf_ct_maps_ struct bf_ct_maps *maps = NULL;
    struct ct_spi_reverse_key key = {};
    __u32 orig_spi = 0xdeadbeef;
    __u32 out = 0;
    int map_fd;
    int r;

    (void)state;

    assert_ok(bf_lock_init(&lock, BF_LOCK_WRITE));

    assert_ok(bf_ct_maps_init(&maps, lock.pindir_fd, NULL));

    map_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SPI_REVERSE);
    assert_int_gt(map_fd, 0);

    key.lo_ip = _be32(10, 0, 0, 1);
    key.hi_ip = _be32(10, 0, 0, 2);
    key.reply_spi = 0xcafebabe;
    key.proto = IPPROTO_ESP;

    r = bf_bpf_map_update_elem(map_fd, &key, &orig_spi, BPF_ANY);
    assert_ok(r);

    r = bf_bpf_map_lookup_elem(map_fd, &key, &out);
    assert_ok(r);
    assert_int_equal(out, orig_spi);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(maps_bpf_entry_roundtrip,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(maps_bpf_reopen_pinned,
                                        _bft_setup_ctx_bpffs,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(maps_bpf_spi_reverse_roundtrip,
                                        _bft_setup_ctx_bpffs,
                                        _bft_teardown_ctx_bpffs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
