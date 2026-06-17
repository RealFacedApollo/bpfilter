// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>

#include <linux/bpf.h>

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <bpfilter/bpf.h>
#include <bpfilter/logger.h>

int bf_ct_meta_get(struct ct_meta *out, const struct bf_ct_maps *maps)
{
    __u32 key = 0;
    int fd;
    int r;

    assert(out);
    assert(maps);

    fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_META);
    if (fd < 0)
        return fd;

    memset(out, 0, sizeof(*out));

    r = bf_bpf_map_lookup_elem(fd, &key, out);
    if (r)
        return bf_err_r(r, "failed to read ct_meta map");

    return 0;
}

int bf_ct_meta_set_last_sweep_ns(const struct bf_ct_maps *maps, __u64 ns)
{
    struct ct_meta meta;
    __u32 key = 0;
    int fd;
    int r;

    assert(maps);

    fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_META);
    if (fd < 0)
        return fd;

    r = bf_ct_meta_get(&meta, maps);
    if (r)
        return r;

    meta.last_sweep_ns = ns;

    r = bf_bpf_map_update_elem(fd, &key, &meta, BPF_ANY);
    if (r)
        return bf_err_r(r, "failed to update ct_meta last_sweep_ns");

    return 0;
}

int bf_ct_maps_init_meta(struct bf_ct_maps *maps)
{
    struct ct_meta meta = {};
    __u32 key = 0;
    int fd;
    int r;

    assert(maps);

    fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_META);
    if (fd < 0)
        return fd;

    r = bf_bpf_map_lookup_elem(fd, &key, &meta);
    if (r && r != -ENOENT)
        return bf_err_r(r, "failed to read ct_meta map");

    if (!meta.key_norm_version)
        meta.key_norm_version = BF_CT_KEY_NORM_VERSION;

    r = bf_bpf_map_update_elem(fd, &key, &meta, BPF_ANY);
    if (r)
        return bf_err_r(r, "failed to initialize ct_meta map");

    return 0;
}

int bf_ct_maps_check_reload(const struct bf_ct_maps *maps)
{
    struct ct_meta meta;
    int r;

    assert(maps);

    r = bf_ct_meta_get(&meta, maps);
    if (r)
        return r;

    if (meta.key_norm_version == BF_CT_KEY_NORM_VERSION)
        return 0;

    return bf_err_r(
        -EINVAL,
        "conntrack key normalization version mismatch (pinned=%u, "
        "expected=%u); remove pinned maps under $BPFFS/bpfilter/ct/ before "
        "reload",
        meta.key_norm_version, BF_CT_KEY_NORM_VERSION);
}
