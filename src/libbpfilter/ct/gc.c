/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpfilter/bpf.h>
#include <bpfilter/ct.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#define _BF_CT_GC_FLOW_MAPS 4

static const enum bf_ct_map_id _bf_ct_gc_map_ids[_BF_CT_GC_FLOW_MAPS] = {
    BF_CT_MAP_TCP,
    BF_CT_MAP_TCP6,
    BF_CT_MAP_ANY,
    BF_CT_MAP_ANY6,
};

static const bool _bf_ct_gc_map_is_v6[_BF_CT_GC_FLOW_MAPS] = {
    false,
    true,
    false,
    true,
};

static __u64 _bf_ct_gc_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;

    return (__u64)ts.tv_sec * BF_CT_NS_PER_S + (__u64)ts.tv_nsec;
}

static int _bf_ct_gc_flow_slot(int map_idx)
{
    switch (map_idx) {
    case 0:
    case 1:
        return 0;
    case 2:
    case 3:
        return 1;
    default:
        return -1;
    }
}

static void *_bf_ct_gc_cursor_ptr(struct bf_ct_gc *gc, int map_idx)
{
    int slot = _bf_ct_gc_flow_slot(map_idx);

    if (slot < 0)
        return NULL;

    if (_bf_ct_gc_map_is_v6[map_idx])
        return &gc->cursor_v6[slot];

    return &gc->cursor_v4[slot];
}

static size_t _bf_ct_gc_key_size(int map_idx)
{
    return _bf_ct_gc_map_is_v6[map_idx] ? sizeof(struct ct_key_v6) :
                                          sizeof(struct ct_key_v4);
}

static int _bf_ct_gc_read_timeouts(int timeouts_fd,
                                   struct ct_timeouts *timeouts)
{
    __u32 key = 0;
    int r;

    assert(timeouts);

    r = bf_bpf_map_lookup_elem(timeouts_fd, &key, timeouts);
    if (r)
        return bf_err_r(r, "failed to read ct_timeouts map");

    return 0;
}

/* Reconstruct the per-source key for the rate/count maps from a flow key.
 *
 * The flow key holds the full source and destination addresses (normalized to
 * lo_ip/hi_ip); @c orig_lo_is_src records which side was the connection's
 * originator. Deriving the source from the key matches what the datapath does
 * at create time and, crucially, works for IPv6: @ref ct_entry only stores the
 * low four bytes of a v6 source in @c orig_src_ip, which is not enough to
 * rebuild the key. */
static void _bf_ct_gc_src_ip_key(const void *key, bool is_v6,
                                 __u8 orig_lo_is_src, struct ct_ip_key *ip_key)
{
    if (is_v6) {
        const struct ct_key_v6 *k = key;
        const struct in6_addr *src = orig_lo_is_src ? &k->lo_ip : &k->hi_ip;

        bf_ct_ip_key_from_v6(src, ip_key);
    } else {
        const struct ct_key_v4 *k = key;
        __be32 src = orig_lo_is_src ? k->lo_ip : k->hi_ip;

        bf_ct_ip_key_from_v4(src, ip_key);
    }
}

static int _bf_ct_gc_src_count_dec(int src_count_fd, const void *key,
                                   bool is_v6, __u8 orig_lo_is_src)
{
    struct ct_ip_key ip_key;
    struct ct_src_count_entry entry;
    int r;

    _bf_ct_gc_src_ip_key(key, is_v6, orig_lo_is_src, &ip_key);

    r = bf_bpf_map_lookup_elem(src_count_fd, &ip_key, &entry);
    if (r) {
        if (r == -ENOENT)
            return 0;
        return r;
    }

    if (entry.count == 0)
        return 0;

    entry.count--;
    if (entry.count == 0)
        return bf_bpf_map_delete_elem(src_count_fd, &ip_key);

    return bf_bpf_map_update_elem(src_count_fd, &ip_key, &entry, BPF_EXIST);
}

/* Delete the corpses collected during a sweep. Each key is re-checked before
 * deletion: the datapath may have replaced a DYING entry with a fresh one for
 * the same flow key since the sweep visited it, and deleting the replacement
 * would reap a live connection. */
static int _bf_ct_gc_flush_deletions(int map_fd, int src_count_fd, bool is_v6,
                                     const char *del_keys, size_t key_size,
                                     size_t n_del, __u64 *phase2)
{
    struct ct_entry entry;
    int r;

    for (size_t i = 0; i < n_del; ++i) {
        const void *key = &del_keys[i * key_size];

        r = bf_bpf_map_lookup_elem(map_fd, key, &entry);
        if (r == -ENOENT)
            continue;
        if (r)
            return r;

        if (!(entry.flags & CT_FLAG_DYING))
            continue;

        r = bf_bpf_map_delete_elem(map_fd, key);
        if (r == -ENOENT)
            continue;
        if (r)
            return r;

        r = _bf_ct_gc_src_count_dec(src_count_fd, key, is_v6,
                                    entry.orig_lo_is_src);
        if (r)
            return r;

        (*phase2)++;
    }

    return 0;
}

static int _bf_ct_gc_sweep_map(int map_fd, int src_count_fd,
                               struct bf_ct_gc *gc, int map_idx,
                               const struct ct_timeouts *timeouts, __u64 now_ns,
                               unsigned batch_size, bool track_completion,
                               __u64 *phase1, __u64 *phase2)
{
    char prev_key[sizeof(struct ct_key_v6)];
    char next_key[sizeof(struct ct_key_v6)];
    _cleanup_free_ char *del_keys = NULL;
    const void *prev = NULL;
    struct ct_entry entry;
    size_t key_size = _bf_ct_gc_key_size(map_idx);
    size_t n_del = 0;
    unsigned swept = 0;
    int r;

    if (track_completion && gc->map_completed[map_idx])
        return 0;

    /* Corpse deletions are deferred until the walk completes: deleting a key
     * mid-walk invalidates it as a bpf_map_get_next_key() cursor, and for hash
     * maps the kernel then restarts iteration from the first bucket — O(reaped
     * × head-length) syscalls per batch, and entries near the end of the
     * iteration order are starved. */
    del_keys = malloc((size_t)batch_size * key_size);
    if (!del_keys)
        return -ENOMEM;

    if (gc->cursor_valid[map_idx]) {
        memcpy(prev_key, _bf_ct_gc_cursor_ptr(gc, map_idx), key_size);
        prev = prev_key;
    }

    while (swept < batch_size) {
        r = bf_bpf_map_get_next_key(map_fd, prev, next_key);
        if (r == -ENOENT) {
            gc->cursor_valid[map_idx] = false;
            if (track_completion)
                gc->map_completed[map_idx] = true;
            break;
        }
        if (r)
            return r;

        memcpy(prev_key, next_key, key_size);
        prev = prev_key;

        r = bf_bpf_map_lookup_elem(map_fd, next_key, &entry);
        if (r) {
            if (r == -ENOENT)
                continue;
            return r;
        }

        if (entry.flags & CT_FLAG_DYING) {
            memcpy(&del_keys[n_del * key_size], next_key, key_size);
            n_del++;
            /* A queued key is about to disappear: it can't serve as the next
             * batch's cursor, so the persisted cursor stays on the last
             * visited key that survives the flush. */
            swept++;
            continue;
        }

        /* The datapath updates last_seen_ns with bpf_ktime_get_ns() while the
         * sweep is in flight, so an entry touched after the now_ns snapshot
         * has last_seen_ns > now_ns: without the first check, the unsigned
         * subtraction wraps and the freshest entries are reaped. */
        if (entry.last_seen_ns <= now_ns &&
            now_ns - entry.last_seen_ns >
                bf_ct_get_timeout_ns(&entry, timeouts)) {
            entry.flags |= CT_FLAG_DYING;

            r = bf_bpf_map_update_elem(map_fd, next_key, &entry, BPF_EXIST);
            if (r)
                return r;

            (*phase1)++;
        }

        memcpy(_bf_ct_gc_cursor_ptr(gc, map_idx), next_key, key_size);
        gc->cursor_valid[map_idx] = true;
        swept++;
    }

    return _bf_ct_gc_flush_deletions(map_fd, src_count_fd,
                                     _bf_ct_gc_map_is_v6[map_idx], del_keys,
                                     key_size, n_del, phase2);
}

void bf_ct_gc_init(struct bf_ct_gc *gc)
{
    assert(gc);

    memset(gc, 0, sizeof(*gc));
}

int bf_ct_gc_sweep_batch(const struct bf_ct_maps *maps, struct bf_ct_gc *gc,
                         const struct bf_ct_gc_opts *opts)
{
    struct ct_timeouts timeouts;
    __u64 phase1 = 0;
    __u64 phase2 = 0;
    __u64 now_ns;
    unsigned batch_size;
    bool track_completion;
    int timeouts_fd;
    int src_count_fd;
    int r;
    int i;

    assert(maps);
    assert(gc);
    assert(opts);

    batch_size = opts->batch_size ? opts->batch_size : BF_CT_GC_BATCH_SIZE;
    track_completion = opts->track_completion;

    timeouts_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TIMEOUTS);
    if (timeouts_fd < 0)
        return timeouts_fd;

    src_count_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SRC_COUNT);
    if (src_count_fd < 0)
        return src_count_fd;

    r = _bf_ct_gc_read_timeouts(timeouts_fd, &timeouts);
    if (r)
        return r;

    now_ns = _bf_ct_gc_now_ns();
    if (!now_ns)
        return bf_err_r(-errno, "failed to read monotonic clock");

    for (i = 0; i < _BF_CT_GC_FLOW_MAPS; ++i) {
        int map_fd = bf_ct_maps_get_fd(maps, _bf_ct_gc_map_ids[i]);

        if (map_fd < 0)
            return map_fd;

        if (track_completion && gc->map_completed[i])
            continue;

        r = _bf_ct_gc_sweep_map(map_fd, src_count_fd, gc, i, &timeouts, now_ns,
                                batch_size, track_completion, &phase1, &phase2);
        if (r)
            return r;
    }

    if (phase1 || phase2) {
        r = bf_ct_meta_add_gc_stats(maps, phase1, phase2);
        if (r)
            return r;
    }

    r = bf_ct_meta_set_last_sweep_ns(maps, now_ns);
    if (r)
        return r;

    return 0;
}

static int _bf_ct_gc_ip_key_cmp(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(struct ct_ip_key));
}

/* Append the source key of every live entry in @p map_fd to @p arr, growing it
 * as needed. The array is the userspace accumulator for the src_count
 * reconciliation: one element per flow entry, later sorted to tally per-source
 * counts. */
static int _bf_ct_gc_collect_sources(int map_fd, bool is_v6,
                                     struct ct_ip_key **arr, size_t *len,
                                     size_t *cap)
{
    char prev_key[sizeof(struct ct_key_v6)];
    char next_key[sizeof(struct ct_key_v6)];
    const void *prev = NULL;
    struct ct_entry entry;
    size_t key_size = is_v6 ? sizeof(struct ct_key_v6) :
                              sizeof(struct ct_key_v4);
    int r;

    while (true) {
        r = bf_bpf_map_get_next_key(map_fd, prev, next_key);
        if (r == -ENOENT)
            break;
        if (r)
            return r;

        memcpy(prev_key, next_key, key_size);
        prev = prev_key;

        r = bf_bpf_map_lookup_elem(map_fd, next_key, &entry);
        if (r) {
            if (r == -ENOENT)
                continue;
            return r;
        }

        /* A DYING entry is already scheduled for deletion (which decrements
         * src_count); counting it here would inflate the rebuilt counts by the
         * number of pending corpses. */
        if (entry.flags & CT_FLAG_DYING)
            continue;

        if (*len == *cap) {
            size_t ncap = *cap ? *cap * 2 : 1024;
            struct ct_ip_key *narr = realloc(*arr, ncap * sizeof(**arr));

            if (!narr)
                return -ENOMEM;
            *arr = narr;
            *cap = ncap;
        }

        _bf_ct_gc_src_ip_key(next_key, is_v6, entry.orig_lo_is_src,
                             &(*arr)[*len]);
        (*len)++;
    }

    return 0;
}

/* Delete src_count entries whose source no longer appears in the (sorted)
 * live-source set @p srcs. Mirrors the delete-while-iterating cursor handling
 * used by _bf_ct_gc_sweep_map(). */
static int _bf_ct_gc_prune_src_count(int src_count_fd,
                                     const struct ct_ip_key *srcs, size_t len)
{
    struct ct_ip_key prev_key;
    struct ct_ip_key next_key;
    const void *prev = NULL;
    int r;

    while (true) {
        r = bf_bpf_map_get_next_key(src_count_fd, prev, &next_key);
        if (r == -ENOENT)
            break;
        if (r)
            return r;

        prev_key = next_key;
        prev = &prev_key;

        if (!bsearch(&next_key, srcs, len, sizeof(*srcs),
                     _bf_ct_gc_ip_key_cmp)) {
            r = bf_bpf_map_delete_elem(src_count_fd, &next_key);
            if (r && r != -ENOENT)
                return r;
        }
    }

    return 0;
}

int bf_ct_gc_reconcile_src_count(const struct bf_ct_maps *maps)
{
    struct ct_ip_key *srcs = NULL;
    size_t len = 0;
    size_t cap = 0;
    size_t i;
    int src_count_fd;
    int r;

    assert(maps);

    src_count_fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_SRC_COUNT);
    if (src_count_fd < 0)
        return src_count_fd;

    for (int m = 0; m < _BF_CT_GC_FLOW_MAPS; ++m) {
        int map_fd = bf_ct_maps_get_fd(maps, _bf_ct_gc_map_ids[m]);

        if (map_fd < 0) {
            r = map_fd;
            goto out;
        }

        r = _bf_ct_gc_collect_sources(map_fd, _bf_ct_gc_map_is_v6[m], &srcs,
                                      &len, &cap);
        if (r)
            goto out;
    }

    qsort(srcs, len, sizeof(*srcs), _bf_ct_gc_ip_key_cmp);

    /* Walk sorted runs of identical sources and write the recomputed count.
     * Writing the exact value (rather than zero-then-increment) avoids a window
     * where the datapath cap check could see an under-count. */
    i = 0;
    while (i < len) {
        struct ct_src_count_entry count;
        size_t j = i + 1;

        while (j < len && memcmp(&srcs[i], &srcs[j], sizeof(srcs[i])) == 0)
            j++;

        count.count = (__u32)(j - i);
        count._pad = 0;
        r = bf_bpf_map_update_elem(src_count_fd, &srcs[i], &count, BPF_ANY);
        if (r)
            goto out;

        i = j;
    }

    r = _bf_ct_gc_prune_src_count(src_count_fd, srcs, len);

out:
    free(srcs);
    return r;
}

int bf_ct_gc_sweep_full(const struct bf_ct_maps *maps, struct bf_ct_gc *gc,
                        const struct bf_ct_gc_opts *opts)
{
    struct bf_ct_gc_opts full_opts;
    bool all_completed;
    int r;
    int i;

    assert(maps);
    assert(gc);
    assert(opts);

    bf_ct_gc_init(gc);

    full_opts = *opts;
    if (!full_opts.batch_size)
        full_opts.batch_size = BF_CT_GC_BATCH_SIZE;
    full_opts.track_completion = true;

    do {
        all_completed = true;

        for (i = 0; i < _BF_CT_GC_FLOW_MAPS; ++i) {
            if (!gc->map_completed[i])
                all_completed = false;
        }

        if (all_completed)
            break;

        r = bf_ct_gc_sweep_batch(maps, gc, &full_opts);
        if (r)
            return r;
    } while (true);

    /* Every live entry has now been visited once. Rebuild src_count from the
     * surviving flow entries so it self-heals from LRU evictions (which delete
     * flow entries without running the GC decrement) and from any incremental
     * drift. */
    return bf_ct_gc_reconcile_src_count(maps);
}
