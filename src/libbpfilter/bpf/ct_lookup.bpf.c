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
    return bf_ct_bpf_lookup(ctx, args->maps, args->key_v4, args->key_v6,
                            args->is_reply);
}
