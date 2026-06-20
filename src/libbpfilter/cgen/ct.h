/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <bpfilter/chain.h>

struct bf_matcher;
struct bf_program;

/** Verifier complexity threshold before splitting a chain (§10.5). */
#define BF_CT_PROG_SPLIT_INSNS 8000u

/**
 * @brief Tail-call segment parameters for multi-program chains.
 */
struct bf_program_ctgen
{
    /** First rule index (inclusive) for this segment. */
    uint32_t rule_begin;

    /** Rule index past the last rule (exclusive). Zero means through end. */
    uint32_t rule_end;

    /** Zero-based segment index. */
    uint32_t segment_idx;

    /** Total number of segments. */
    uint32_t segment_total;
};

static inline bool bf_chain_uses_conntrack(const struct bf_chain *chain)
{
    return chain && (chain->flags & BF_FLAG(BF_CHAIN_CONNTRACK));
}

bool bf_program_chain_uses_ct(const struct bf_program *program);

int bf_ct_emit_prologue(struct bf_program *program);
int bf_ct_emit_match(struct bf_program *program,
                     const struct bf_matcher *matcher);
int bf_ct_emit_create_if_new(struct bf_program *program, bool notrack);
int bf_ct_emit_tail_call(struct bf_program *program);
int bf_ct_emit_scratch_restore(struct bf_program *program);
