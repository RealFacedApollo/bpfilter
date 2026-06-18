/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/types.h>

#include <bpfilter/ct.h>

#include "cgen/runtime.h"
#include "ct/bpf/lookup.h"

__u8 bf_ct_lookup(struct bf_runtime *ctx, struct bf_ct_lookup_args *args)
{
    /* Copy the maps into this frame and operate on the local copy. The map
     * pointers are spilled in the caller frame; any helper call that receives
     * a caller-frame pointer (a flow key, the dynptr, ...) makes the verifier
     * scalarize those spills, so a later map access would see a non-map.
     * Taking the address of a local copy forces it into this frame, whose
     * spills survive such helper calls. */
    struct bf_ct_bpf_maps maps;

    /* Field-by-field so each map pointer is a typed copy the verifier tracks;
     * a struct assignment lowers to a byte memcpy that drops the map type. */
    maps.tcp = ctx->ct_maps.tcp;
    maps.tcp6 = ctx->ct_maps.tcp6;
    maps.any = ctx->ct_maps.any;
    maps.any6 = ctx->ct_maps.any6;
    maps.src_rate = ctx->ct_maps.src_rate;
    maps.src_count = ctx->ct_maps.src_count;
    maps.spi_reverse = ctx->ct_maps.spi_reverse;
    maps.stats = ctx->ct_maps.stats;

    return bf_ct_bpf_lookup(ctx, &maps, args->key_v4, args->key_v6,
                            args->is_reply);
}
