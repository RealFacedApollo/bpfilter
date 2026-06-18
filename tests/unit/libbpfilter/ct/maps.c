// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>
#include <bpfilter/ctx.h>

#include <errno.h>
#include <unistd.h>

#include "core/lock.h"
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

static void maps_init_invalid_fd(void **state)
{
    _free_bf_ct_maps_ struct bf_ct_maps *maps = NULL;

    (void)state;

    assert_int_equal(bf_ct_maps_init(&maps, -1, NULL), -EBADFD);
    assert_null(maps);
}

static void ctx_ct_maps_disabled(void **state)
{
    struct bft_tmpdir *tmpdir = *state;

    (void)tmpdir;

    assert_null(bf_ctx_get_ct_maps());
}

static void ctx_ct_maps_lazy(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    const struct bf_ct_maps *ct_maps;
    int fd;

    (void)state;

    // Maps are created lazily: arming them makes them available, and a second
    // call is idempotent.
    assert_ok(bf_lock_init(&lock, BF_LOCK_WRITE));

    assert_ok(bf_ctx_ensure_ct_maps(lock.pindir_fd));

    ct_maps = bf_ctx_get_ct_maps();
    assert_non_null(ct_maps);

    fd = bf_ct_maps_get_fd(ct_maps, BF_CT_MAP_TCP);
    assert_int_gte(fd, 0);

    fd = bf_ct_maps_get_fd(ct_maps, BF_CT_MAP_META);
    assert_int_gte(fd, 0);

    assert_int_equal(bf_ct_maps_get_fd(ct_maps, _BF_CT_MAP_MAX), -EINVAL);

    assert_ok(bf_ctx_ensure_ct_maps(lock.pindir_fd));
    assert_ptr_equal(bf_ctx_get_ct_maps(), ct_maps);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(maps_init_invalid_fd),
        cmocka_unit_test_setup_teardown(ctx_ct_maps_disabled, bft_setup_ctx,
                                        bft_teardown_ctx),
        cmocka_unit_test_setup_teardown(ctx_ct_maps_lazy,
                                        _bft_setup_ctx_bpffs_ct,
                                        _bft_teardown_ctx_bpffs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
