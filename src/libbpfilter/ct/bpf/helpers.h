/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>
#include <linux/types.h>

#if defined(BF_CT_BPF_WITH_LIBBPF_HELPERS)
#include <bpf/bpf_helpers.h>
#else
extern void *bpf_map_lookup_elem(void *map, const void *key);
extern long bpf_map_update_elem(void *map, const void *key, const void *value,
                                __u64 flags);
extern __u64 bpf_ktime_get_ns(void);
#endif
