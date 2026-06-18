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
    /* The CT maps are referenced as host-global relocatable maps (see
     * ct/bpf/maps.h): each bpf_map_lookup_elem() operand is a BPF_LD_MAP_FD
     * constant the elfstub loader patches with the real pinned map fd. No map
     * pointer is carried through the runtime struct or this frame's stack, so
     * the verifier keeps the map type across the subprogram's helper calls.
     * args->maps is unused (the create stub still uses the struct path). */
    return bf_ct_bpf_lookup(ctx, args->key_v4, args->key_v6, args->is_reply);
}
