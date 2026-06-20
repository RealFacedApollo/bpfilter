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
    /* The CT maps are referenced as host-global relocatable maps (see
     * ct/bpf/maps.h): each map operand is a BPF_LD_MAP_FD constant the elfstub
     * loader patches with the real pinned map fd. No map pointer is carried
     * through the runtime struct or this frame's stack, so the verifier keeps
     * the map type across the subprogram's helper calls. */
    return bf_ct_bpf_create_if_new(ctx, args->ct_state, args->is_v6,
                                   args->key_v4, args->key_v6);
}
