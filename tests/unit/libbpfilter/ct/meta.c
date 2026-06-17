// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <bpfilter/bpf.h>
#include <bpfilter/ct.h>
#include <bpfilter/ctx.h>

#include <errno.h>
#include <unistd.h>

#include "test.h"

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

static void meta_init_and_reload_check(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_meta meta = {};

    (void)state;

    assert_non_null(maps);
    assert_ok(bf_ct_maps_check_reload(maps));
    assert_ok(bf_ct_meta_get(&meta, maps));
    assert_int_equal(meta.key_norm_version, BF_CT_KEY_NORM_VERSION);
}

static void meta_reload_version_mismatch(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_meta meta = {};
    __u32 key = 0;
    int fd;
    int r;

    (void)state;

    assert_non_null(maps);
    assert_ok(bf_ct_meta_get(&meta, maps));

    meta.key_norm_version = 0;
    fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_META);
    assert_int_gte(fd, 0);

    r = bf_bpf_map_update_elem(fd, &key, &meta, BPF_ANY);
    assert_ok(r);

    assert_int_equal(bf_ct_maps_check_reload(maps), -EINVAL);

    meta.key_norm_version = BF_CT_KEY_NORM_VERSION;
    assert_ok(bf_bpf_map_update_elem(fd, &key, &meta, BPF_ANY));
    assert_ok(bf_ct_maps_check_reload(maps));
}

static void meta_last_sweep_ns(void **state)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_meta meta = {};
    __u64 ts = 424242ULL * BF_CT_NS_PER_S;

    (void)state;

    assert_non_null(maps);
    assert_ok(bf_ct_meta_set_last_sweep_ns(maps, ts));
    assert_ok(bf_ct_meta_get(&meta, maps));
    assert_int_equal(meta.last_sweep_ns, ts);
    assert_int_equal(meta.key_norm_version, BF_CT_KEY_NORM_VERSION);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(meta_init_and_reload_check,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(meta_reload_version_mismatch,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
        cmocka_unit_test_setup_teardown(meta_last_sweep_ns,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
