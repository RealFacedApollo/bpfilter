/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "ct.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <bpfilter/ct.h>
#include <bpfilter/ctx.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "opts.h"

static volatile sig_atomic_t _bfc_ct_gc_stop;

static void _bfc_ct_gc_on_signal(int sig)
{
    (void)sig;

    _bfc_ct_gc_stop = 1;
}

static int _bfc_ct_gc_install_signals(void)
{
    struct sigaction sa = {
        .sa_handler = _bfc_ct_gc_on_signal,
    };

    if (sigaction(SIGINT, &sa, NULL))
        return bf_err_r(-errno, "failed to install SIGINT handler");
    if (sigaction(SIGTERM, &sa, NULL))
        return bf_err_r(-errno, "failed to install SIGTERM handler");

    return 0;
}

static struct bf_ct_gc_opts _bfc_ct_gc_opts_from(const struct bfc_opts *opts)
{
    struct bf_ct_gc_opts gc_opts = {
        .batch_size =
            opts->gc_batch_size ? opts->gc_batch_size : BF_CT_GC_BATCH_SIZE,
    };

    return gc_opts;
}

int bfc_ct_gc_sweep(const struct bfc_opts *opts)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct bf_ct_gc gc;
    struct bf_ct_gc_opts gc_opts;

    assert(opts);

    if (!maps)
        return bf_err_r(-EINVAL, "conntrack maps are not initialized");

    gc_opts = _bfc_ct_gc_opts_from(opts);

    if (opts->gc_once)
        return bf_ct_gc_sweep_full(maps, &gc, &gc_opts);

    bf_ct_gc_init(&gc);
    return bf_ct_gc_sweep_batch(maps, &gc, &gc_opts);
}

int bfc_ct_gc_run(const struct bfc_opts *opts)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct bf_ct_gc gc;
    struct bf_ct_gc_opts gc_opts;
    unsigned interval;
    unsigned reconcile_every;
    unsigned since_reconcile = 0;
    int r;

    assert(opts);

    if (!maps)
        return bf_err_r(-EINVAL, "conntrack maps are not initialized");

    r = _bfc_ct_gc_install_signals();
    if (r)
        return r;

    gc_opts = _bfc_ct_gc_opts_from(opts);
    interval =
        opts->gc_interval_sec ? opts->gc_interval_sec : BF_CT_GC_INTERVAL_SEC;

    /* sweep_batch decrements src_count only for entries it reaps; LRU evictions
     * bypass it, so the count drifts up over time. Periodically rebuild it from
     * the live entries. Aim for roughly one reconciliation per minute,
     * regardless of the sweep interval. */
    reconcile_every = (60u + interval - 1) / (interval ? interval : 1);
    if (!reconcile_every)
        reconcile_every = 1;

    bf_ct_gc_init(&gc);

    while (!_bfc_ct_gc_stop) {
        r = bf_ct_gc_sweep_batch(maps, &gc, &gc_opts);
        if (r)
            return r;

        if (++since_reconcile >= reconcile_every) {
            r = bf_ct_gc_reconcile_src_count(maps);
            if (r)
                return r;

            since_reconcile = 0;
        }

        for (unsigned i = 0; i < interval && !_bfc_ct_gc_stop; ++i)
            sleep(1);
    }

    return 0;
}

static __u64 _bfc_ct_gc_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;

    return (__u64)ts.tv_sec * BF_CT_NS_PER_S + (__u64)ts.tv_nsec;
}

int bfc_ct_gc_status(const struct bfc_opts *opts)
{
    const struct bf_ct_maps *maps = bf_ctx_get_ct_maps();
    struct ct_meta meta = {};
    __u64 now_ns;
    bool stale;
    int r;

    assert(opts);

    (void)opts;

    if (!maps)
        return bf_err_r(-EINVAL, "conntrack maps are not initialized");

    r = bf_ct_meta_get(&meta, maps);
    if (r)
        return r;

    now_ns = _bfc_ct_gc_now_ns();
    stale = !meta.last_sweep_ns ||
            now_ns < meta.last_sweep_ns ||
            (now_ns - meta.last_sweep_ns) > BF_CT_GC_STALE_THRESHOLD_NS;

    printf("key_norm_version=%u\n", meta.key_norm_version);
    printf("last_sweep_ns=%llu\n", (unsigned long long)meta.last_sweep_ns);
    printf("stale=%d\n", stale ? 1 : 0);

    return 0;
}
