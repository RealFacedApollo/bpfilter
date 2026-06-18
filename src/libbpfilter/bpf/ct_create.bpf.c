/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/types.h>

#include <bpfilter/ct.h>

#include "cgen/runtime.h"
#include "ct/bpf/create.h"

__u8 bf_ct_create_if_new(struct bf_runtime *ctx, struct bf_ct_create_args *args)
{
    /* Field-by-field typed copy into this frame; see bf_ct_lookup(). */
    struct bf_ct_bpf_maps maps;

    maps.tcp = ctx->ct_maps.tcp;
    maps.tcp6 = ctx->ct_maps.tcp6;
    maps.any = ctx->ct_maps.any;
    maps.any6 = ctx->ct_maps.any6;
    maps.src_rate = ctx->ct_maps.src_rate;
    maps.src_count = ctx->ct_maps.src_count;
    maps.spi_reverse = ctx->ct_maps.spi_reverse;
    maps.stats = ctx->ct_maps.stats;

    return bf_ct_bpf_create_if_new(ctx, &maps, args->ct_state, args->is_v6,
                                   args->key_v4, args->key_v6);
}
