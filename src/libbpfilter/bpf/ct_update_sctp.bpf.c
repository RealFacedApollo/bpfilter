/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/types.h>

#include <bpfilter/ct.h>

#include "ct/bpf/state.h"

void bf_ct_update_sctp_state(struct ct_entry *entry, __u8 chunk_type,
                             __u8 is_reply)
{
    bf_ct_bpf_sctp_fsm(entry, chunk_type, is_reply);
}
