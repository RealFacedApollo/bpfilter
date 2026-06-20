/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/types.h>

static __always_inline void
bf_ct_bpf_ipsec_record_reply(struct ct_entry *entry, void *spi_reverse_map,
                             __be32 lo_ip, __be32 hi_ip, __u8 proto,
                             __u32 reply_spi,
                             struct ct_spi_reverse_key *rev_key)
{
    __u32 orig_spi;

    if (entry->reply_discriminator)
        return;

    entry->reply_discriminator = reply_spi;

    orig_spi = entry->orig_discriminator;
    /* rev_key is staged in the per-CPU scratch map by the caller. */
    __builtin_memset(rev_key, 0, sizeof(*rev_key));
    rev_key->lo_ip = lo_ip;
    rev_key->hi_ip = hi_ip;
    rev_key->reply_spi = reply_spi;
    rev_key->proto = proto;

    bpf_map_update_elem(spi_reverse_map, rev_key, &orig_spi, BPF_ANY);
}
