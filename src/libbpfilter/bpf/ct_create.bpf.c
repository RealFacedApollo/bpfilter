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
    return bf_ct_bpf_create_if_new(ctx, args->maps, args->ct_state, args->is_v6,
                                   args->key_v4, args->key_v6);
}
