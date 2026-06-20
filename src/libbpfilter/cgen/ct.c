/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/ct.h"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/btf.h>
#include <bpfilter/ctx.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>

#include "cgen/jmp.h"
#include "cgen/program.h"
#include "filter.h"

#define _BF_CT_RUNTIME_OFF(field)                                              \
    (-(int)sizeof(struct bf_runtime) + (int)offsetof(struct bf_runtime, field))

static int _bf_ct_emit_runtime_reg(struct bf_program *program, int reg)
{
    EMIT(program, BPF_MOV64_REG(reg, BPF_REG_10));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, reg, -(int)sizeof(struct bf_runtime)));

    return 0;
}

static bool _bf_ct_hook_has_skb(enum bf_hook hook)
{
    switch (hook) {
    case BF_HOOK_TC_INGRESS:
    case BF_HOOK_TC_EGRESS:
    case BF_HOOK_CGROUP_SKB_INGRESS:
    case BF_HOOK_CGROUP_SKB_EGRESS:
        return true;
    default:
        return false;
    }
}

static int _bf_ct_emit_hairpin_skip(struct bf_program *program)
{
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_hairpin_skip), 1));
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_state),
                             0));
    return 0;
}

static int _bf_ct_emit_hairpin_invalidate_scratch(struct bf_program *program)
{
    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, 0));
    EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, BF_CT_MAP_TAIL_SCRATCH);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_2, 0, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    {
        _clean_bf_jmpctx_ struct bf_jmpctx miss =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        EMIT(program,
             BPF_ST_MEM(BPF_B, BPF_REG_0,
                        offsetof(struct ct_tail_scratch, ct_state_valid), 0));
    }

    return 0;
}

static int _bf_ct_emit_skb_cb_load(struct bf_program *program, int cb_off)
{
    _bf_ct_emit_runtime_reg(program, BPF_REG_6);
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_6,
                              offsetof(struct bf_runtime, arg)));
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_9, cb_off));

    return 0;
}

/**
 * Hairpin processed path: invalidate tail scratch (segment N>0) and skip CT.
 */
static int _bf_ct_emit_hairpin_processed_path(struct bf_program *program,
                                              bool invalidate_scratch)
{
    int r;

    if (invalidate_scratch) {
        r = _bf_ct_emit_hairpin_invalidate_scratch(program);
        if (r)
            return r;
    }

    return _bf_ct_emit_hairpin_skip(program);
}

static int _bf_ct_emit_lookup_call(struct bf_program *program)
{
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_hairpin_skip),
                             0));
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_is_reply),
                             0));
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_is_v6), 0));

    /* lo_ip and hi_ip are adjacent 4-byte fields: a single 8-byte store zeroes
     * both while keeping the stack access 8-byte aligned. Storing hi_ip
     * separately as a double word would land on a 4-byte-aligned offset and
     * the verifier rejects it ("misaligned stack access"). */
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v4.lo_ip), 0));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v4.discriminator), 0));
    /* Word store covers proto and the 3 padding bytes: the whole key must be
     * initialized before it is used as a map lookup key, or the verifier
     * rejects the program with "invalid indirect read from stack". */
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_key_v4.proto),
                             0));

    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v6.lo_ip), 0));
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v6.lo_ip) + 8, 0));
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v6.hi_ip), 0));
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v6.hi_ip) + 8, 0));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v6.discriminator), 0));
    /* Word store covers proto and the 3 padding bytes (see ct_key_v4 above). */
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_key_v6.proto),
                             0));

    /* Build struct bf_ct_lookup_args in the scratch area: key_v4 (offset 0),
     * key_v6 (offset 8), is_reply (offset 16). The CT maps are referenced as
     * relocatable globals inside the stub, so no map pointer is passed. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v4)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v6)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(8)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_is_reply)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(16)));

    _bf_ct_emit_runtime_reg(program, BPF_REG_1);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_CT_LOOKUP);

    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_0,
                              _BF_CT_RUNTIME_OFF(ct_state)));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_key_v6.proto)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx v6 =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

        EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_is_v6),
                                 1));
    }

    return 0;
}

static int _bf_ct_emit_copy_key_v4(struct bf_program *program, int src_reg)
{
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, src_reg,
                              (int)offsetof(struct ct_tail_scratch, key_v4.lo_ip)));
    EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_key_v4.lo_ip)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, src_reg,
                              (int)offsetof(struct ct_tail_scratch, key_v4.hi_ip)));
    EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_key_v4.hi_ip)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, src_reg,
                              (int)offsetof(struct ct_tail_scratch,
                                            key_v4.discriminator)));
    EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_key_v4.discriminator)));
    /* Zero proto and the 3 padding bytes first, then overwrite the proto byte:
     * the copy only fills the named fields, so the pad would otherwise stay
     * uninitialized and fail verification when the key is looked up. */
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_key_v4.proto),
                             0));
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, src_reg,
                              (int)offsetof(struct ct_tail_scratch, key_v4.proto)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_key_v4.proto)));
    return 0;
}

static int _bf_ct_emit_copy_key_v6(struct bf_program *program, int src_reg)
{
    size_t i;

    for (i = 0; i < sizeof(struct ct_key_v6); i += 4) {
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, src_reg,
                                  (int)(offsetof(struct ct_tail_scratch,
                                                 key_v6) +
                                        i)));
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                  _BF_CT_RUNTIME_OFF(ct_key_v6) + (int)i));
    }

    return 0;
}

static int _bf_ct_emit_scratch_apply(struct bf_program *program, int src_reg)
{
    int r;

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, src_reg,
                     offsetof(struct ct_tail_scratch, ct_state)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_state)));

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, src_reg,
                     offsetof(struct ct_tail_scratch, is_reply)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_is_reply)));

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, src_reg,
                     offsetof(struct ct_tail_scratch, is_v6)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1,
                              _BF_CT_RUNTIME_OFF(ct_is_v6)));

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, src_reg,
                     offsetof(struct ct_tail_scratch, is_v6)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx v4 =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

        r = _bf_ct_emit_copy_key_v6(program, src_reg);
        if (r)
            return r;
    }

    return _bf_ct_emit_copy_key_v4(program, src_reg);
}

bool bf_program_chain_uses_ct(const struct bf_program *program)
{
    assert(program);

    if (!bf_chain_uses_conntrack(program->runtime.chain))
        return false;

    return bf_ctx_get_ct_maps() != NULL;
}

int bf_ct_emit_scratch_restore(struct bf_program *program)
{
    if (!bf_program_chain_uses_ct(program))
        return 0;

    if (program->ctgen.segment_idx == 0)
        return 0;

    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, 0));
    EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, BF_CT_MAP_TAIL_SCRATCH);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_2, 0, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    {
        _clean_bf_jmpctx_ struct bf_jmpctx miss =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        EMIT(program,
             BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0,
                         offsetof(struct ct_tail_scratch, ct_state_valid)));
        {
            _clean_bf_jmpctx_ struct bf_jmpctx invalid =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

            return _bf_ct_emit_scratch_apply(program, BPF_REG_0);
        }
    }

    return _bf_ct_emit_lookup_call(program);
}

static int _bf_ct_emit_zero_range(struct bf_program *program, int off, int len)
{
    int i = 0;

    for (; i + 8 <= len; i += 8)
        EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, off + i, 0));
    for (; i + 4 <= len; i += 4)
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, off + i, 0));

    return 0;
}

/* Copy a packet header from the dynptr into an embedded runtime buffer so the
 * CT subprogram can read it as struct memory (see bf_ct_bpf_l3/l4). The buffer
 * is zeroed first, so a truncated header reads as zero rather than as
 * uninitialized stack. The length is clamped to the buffer size to keep the
 * read in-bounds for the verifier. */
static int _bf_ct_emit_copy_hdr(struct bf_program *program, int dst_off,
                                int size_off, int offset_off, int slice_len)
{
    int r;

    r = _bf_ct_emit_zero_range(program, dst_off, slice_len);
    if (r)
        return r;

    // len = min(*size_off, slice_len)
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, size_off));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx fits =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JLE, BPF_REG_2, slice_len, 0));

        EMIT(program, BPF_MOV64_IMM(BPF_REG_2, slice_len));
        (void)fits;
    }

    // bpf_dynptr_read(dst, len, &dynptr, offset, 0)
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, dst_off));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, _BF_CT_RUNTIME_OFF(dynptr)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, offset_off));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_5, 0));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_dynptr_read));

    return 0;
}

static int _bf_ct_emit_copy_headers(struct bf_program *program)
{
    int r;

    r = _bf_ct_emit_copy_hdr(program, _BF_CT_RUNTIME_OFF(l3),
                             _BF_CT_RUNTIME_OFF(l3_size),
                             _BF_CT_RUNTIME_OFF(l3_offset), BF_L3_SLICE_LEN);
    if (r)
        return r;

    return _bf_ct_emit_copy_hdr(program, _BF_CT_RUNTIME_OFF(l4),
                                _BF_CT_RUNTIME_OFF(l4_size),
                                _BF_CT_RUNTIME_OFF(l4_offset), BF_L4_SLICE_LEN);
}

int bf_ct_emit_prologue(struct bf_program *program)
{
    int cb_off;
    int r;

    if (!bf_program_chain_uses_ct(program))
        return 0;

    r = _bf_ct_emit_copy_headers(program);
    if (r)
        return r;

    if (_bf_ct_hook_has_skb(program->runtime.chain->hook)) {
        r = bf_btf_get_field_off("__sk_buff", "cb");
        if (r < 0)
            return r;
        cb_off = r + BF_CT_CB_SLOT;

        r = _bf_ct_emit_skb_cb_load(program, cb_off);
        if (r)
            return r;

        {
            /* The first-visit jump must land past the hairpin-skip block, so
             * its fixup has to be resolved after that block is emitted. Keep it
             * alive in this outer scope while the inner `processed` jump
             * resolves to the start of the hairpin-skip block below. */
            _clean_bf_jmpctx_ struct bf_jmpctx first_visit = {0};

            {
                _clean_bf_jmpctx_ struct bf_jmpctx processed =
                    bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1,
                                                       BF_CT_CB_PROCESSED, 0));

                EMIT(program, BPF_MOV64_IMM(BPF_REG_2, BF_CT_CB_PROCESSED));
                EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_9, BPF_REG_2, cb_off));

                if (program->ctgen.segment_idx > 0) {
                    r = bf_ct_emit_scratch_restore(program);
                    if (r)
                        return r;
                } else {
                    r = _bf_ct_emit_lookup_call(program);
                    if (r)
                        return r;
                }

                /* First visit: skip the hairpin-skip block so the conntrack
                 * state computed above is preserved. */
                first_visit = bf_jmpctx_get(program, BPF_JMP_A(0));
            }

            /* Already-processed packet (`processed` jump target): drop the
             * stale conntrack state and mark the packet as hairpin-skipped. */
            r = _bf_ct_emit_hairpin_processed_path(
                program, program->ctgen.segment_idx > 0);
            if (r)
                return r;
        }

        return 0;
    }

    if (program->ctgen.segment_idx > 0)
        return bf_ct_emit_scratch_restore(program);

    return _bf_ct_emit_lookup_call(program);
}

int bf_ct_emit_match(struct bf_program *program,
                     const struct bf_matcher *matcher)
{
    const struct bf_match_ct_payload *ct = bf_matcher_payload(matcher);
    uint8_t mask;

    assert(program);
    assert(matcher);
    assert(ct);

    mask = ct->state_mask;

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_state)));
    EMIT(program, BPF_ALU32_IMM(BPF_AND, BPF_REG_1, mask));

    if (ct->invert) {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));
    }

    return 0;
}

static int _bf_ct_emit_map_select(struct bf_program *program, int proto,
                                  enum bf_ct_map_id tcp_map,
                                  enum bf_ct_map_id any_map)
{
    /* The past-tcp jump must land past the any-map load, so its fixup has to be
     * resolved after that load is emitted. Keep it alive in this outer scope
     * while the inner `not_tcp` jump resolves to the any-map load below. */
    _clean_bf_jmpctx_ struct bf_jmpctx past_tcp = {0};

    {
        _clean_bf_jmpctx_ struct bf_jmpctx not_tcp =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, proto, 0));

        /* proto == tcp_map's protocol: select the protocol-specific map and
         * jump over the any-map fallback. */
        EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, tcp_map);
        past_tcp = bf_jmpctx_get(program, BPF_JMP_A(0));
    }

    /* not_tcp jump target: every other protocol uses the any map. */
    EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, any_map);

    return 0;
}

static int _bf_ct_emit_entry_lookup(struct bf_program *program)
{
    int r;

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_is_v6)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx v6 =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 0));

        r = _bf_ct_emit_map_select(program, IPPROTO_TCP, BF_CT_MAP_TCP6,
                                   BF_CT_MAP_ANY6);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,
                                    _BF_CT_RUNTIME_OFF(ct_key_v6)));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

        return 0;
    }

    r = _bf_ct_emit_map_select(program, IPPROTO_TCP, BF_CT_MAP_TCP,
                               BF_CT_MAP_ANY);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,
                                _BF_CT_RUNTIME_OFF(ct_key_v4)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    return 0;
}

static int _bf_ct_emit_tcp_update(struct bf_program *program)
{
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_is_reply)));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(l4_hdr)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_0));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_CT_UPDATE_TCP);

    return 0;
}

static int _bf_ct_emit_sctp_update(struct bf_program *program)
{
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_is_reply)));
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(l4_hdr)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_0));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_CT_UPDATE_SCTP);

    return 0;
}

int bf_ct_emit_update_fsm(struct bf_program *program)
{
    int r;

    if (!bf_program_chain_uses_ct(program))
        return 0;

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_hairpin_skip)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx hairpin =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 0));

        /* Advance the protocol FSM for every tracked TCP/SCTP packet, not only
         * NEW-classified ones. A reply is now classified ESTABLISHED (see
         * bf_ct_entry_to_rule_state), so the handshake SYN-ACK/ACK are no longer
         * NEW; gating on NEW here would freeze internal_state at SYN_SENT and
         * give established flows the short SYN timeout (see
         * bf_ct_get_timeout_ns). The entry lookup below misses until
         * create_if_new inserts the entry, so running this on the initial SYN is
         * a harmless no-op.
         *
         * TCP and SCTP are mutually exclusive: after the TCP block runs (or its
         * lookup misses), the SCTP test below fails on a TCP packet and jumps
         * over the SCTP block, so no explicit jump-to-end is needed. */
        {
            _clean_bf_jmpctx_ struct bf_jmpctx not_tcp =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8,
                                                   IPPROTO_TCP, 0));

            r = _bf_ct_emit_entry_lookup(program);
            if (r)
                return r;

            {
                _clean_bf_jmpctx_ struct bf_jmpctx miss =
                    bf_jmpctx_get(program,
                                  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

                r = _bf_ct_emit_tcp_update(program);
                if (r)
                    return r;
            }
        }

        {
            _clean_bf_jmpctx_ struct bf_jmpctx not_sctp =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8,
                                                   IPPROTO_SCTP, 0));

            r = _bf_ct_emit_entry_lookup(program);
            if (r)
                return r;

            {
                _clean_bf_jmpctx_ struct bf_jmpctx miss =
                    bf_jmpctx_get(program,
                                  BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

                r = _bf_ct_emit_sctp_update(program);
                if (r)
                    return r;
            }
        }
    }

    return 0;
}

static int _bf_ct_emit_create(struct bf_program *program)
{
    /* Build struct bf_ct_create_args in the scratch area: key_v4 (offset 0),
     * key_v6 (offset 8), ct_state (offset 16), is_v6 (offset 17). */
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v4)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v6)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(8)));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_state)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(16)));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_is_v6)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(17)));

    _bf_ct_emit_runtime_reg(program, BPF_REG_1);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_CT_CREATE);

    return 0;
}

int bf_ct_emit_create_if_new(struct bf_program *program, bool notrack)
{
    int r;

    if (!bf_program_chain_uses_ct(program))
        return 0;

    if (notrack)
        return 0;

    /* Only create an entry for a freshly NEW-classified, non-hairpin packet.
     * Each guard's scope spans the create call so its jump skips over it; the
     * CT_CREATE stub re-checks ct_state == NEW internally as a backstop. */
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_hairpin_skip)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx skip =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_state)));
        {
            _clean_bf_jmpctx_ struct bf_jmpctx not_new = bf_jmpctx_get(
                program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, CT_STATE_NEW, 0));

            r = _bf_ct_emit_create(program);
            if (r)
                return r;
        }
    }

    return 0;
}

int bf_ct_emit_tail_call(struct bf_program *program)
{
    int r;

    if (!bf_program_chain_uses_ct(program))
        return 0;

    if (program->ctgen.segment_idx + 1 >= program->ctgen.segment_total)
        return 0;

    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, 0));
    EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, BF_CT_MAP_TAIL_SCRATCH);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_2, 0, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    {
        _clean_bf_jmpctx_ struct bf_jmpctx miss =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_state)));
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1,
                                  offsetof(struct ct_tail_scratch, ct_state)));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_is_reply)));
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1,
                                  offsetof(struct ct_tail_scratch, is_reply)));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_is_v6)));
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1,
                                  offsetof(struct ct_tail_scratch, is_v6)));

        EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_0,
                                 offsetof(struct ct_tail_scratch,
                                          ct_state_valid),
                                 1));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_is_v6)));
        {
            _clean_bf_jmpctx_ struct bf_jmpctx v4 =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

            r = _bf_ct_emit_copy_key_v6(program, BPF_REG_0);
            if (r)
                return r;
        }

        r = _bf_ct_emit_copy_key_v4(program, BPF_REG_0);
        if (r)
            return r;

        _bf_ct_emit_runtime_reg(program, BPF_REG_1);
        EMIT_LOAD_PROG_ARRAY_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, program->ctgen.segment_idx + 1));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_tail_call));
    }

    return 0;
}
