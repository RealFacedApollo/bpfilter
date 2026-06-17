/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/tcp.h>
#include <linux/types.h>

#include <bpfilter/ct.h>

#include "ct/bpf/state.h"

void bf_ct_update_tcp_state(struct ct_entry *entry, const struct tcphdr *tcp,
                            __u8 is_reply)
{
    bf_ct_bpf_tcp_fsm(entry, tcp, is_reply);
}
