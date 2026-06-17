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

static int _bf_ct_emit_store_map_ptr(struct bf_program *program, int reg,
                                     enum bf_ct_map_id map_id, int field_off)
{
    EMIT_LOAD_CT_MAP_FD_FIXUP(program, reg, map_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, field_off));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_1, reg, 0));

    return 0;
}

static int _bf_ct_emit_populate_maps(struct bf_program *program)
{
    int r;

    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_TCP,
                                  _BF_CT_RUNTIME_OFF(ct_maps.tcp));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_TCP6,
                                  _BF_CT_RUNTIME_OFF(ct_maps.tcp6));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_ANY,
                                  _BF_CT_RUNTIME_OFF(ct_maps.any));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_ANY6,
                                  _BF_CT_RUNTIME_OFF(ct_maps.any6));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_SRC_RATE,
                                  _BF_CT_RUNTIME_OFF(ct_maps.src_rate));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_SRC_COUNT,
                                  _BF_CT_RUNTIME_OFF(ct_maps.src_count));
    if (r)
        return r;
    r = _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_SPI_REVERSE,
                                  _BF_CT_RUNTIME_OFF(ct_maps.spi_reverse));
    if (r)
        return r;

    return _bf_ct_emit_store_map_ptr(program, BPF_REG_1, BF_CT_MAP_STATS,
                                     _BF_CT_RUNTIME_OFF(ct_maps.stats));
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

    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v4.lo_ip), 0));
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v4.hi_ip), 0));
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10,
                             _BF_CT_RUNTIME_OFF(ct_key_v4.discriminator), 0));
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_key_v4.proto),
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
    EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, _BF_CT_RUNTIME_OFF(ct_key_v6.proto),
                             0));

    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_SCR_OFF(0), 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_CT_RUNTIME_OFF(ct_maps)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v4)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(8)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v6)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(16)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_is_reply)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(24)));

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

    r = _bf_ct_emit_copy_key_v4(program, src_reg);
    if (r)
        return r;

    return _bf_ct_emit_populate_maps(program);
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
    int r;

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

    r = _bf_ct_emit_populate_maps(program);
    if (r)
        return r;

    return _bf_ct_emit_lookup_call(program);
}

int bf_ct_emit_prologue(struct bf_program *program)
{
    int cb_off;
    int r;

    if (!bf_program_chain_uses_ct(program))
        return 0;

    if (_bf_ct_hook_has_skb(program->runtime.chain->hook)) {
        r = bf_btf_get_field_off("__sk_buff", "cb");
        if (r < 0)
            return r;
        cb_off = r + BF_CT_CB_SLOT;

        r = _bf_ct_emit_skb_cb_load(program, cb_off);
        if (r)
            return r;

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
                r = _bf_ct_emit_populate_maps(program);
                if (r)
                    return r;

                r = _bf_ct_emit_lookup_call(program);
                if (r)
                    return r;
            }

            {
                _clean_bf_jmpctx_ struct bf_jmpctx first_visit =
                    bf_jmpctx_get(program, BPF_JMP_A(0));

                (void)first_visit;
            }
        }

        return _bf_ct_emit_hairpin_processed_path(
            program, program->ctgen.segment_idx > 0);
    }

    if (program->ctgen.segment_idx > 0)
        return bf_ct_emit_scratch_restore(program);

    r = _bf_ct_emit_populate_maps(program);
    if (r)
        return r;

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
    {
        _clean_bf_jmpctx_ struct bf_jmpctx not_tcp =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, proto, 0));

        EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, any_map);
        {
            _clean_bf_jmpctx_ struct bf_jmpctx past_tcp =
                bf_jmpctx_get(program, BPF_JMP_A(0));

            (void)past_tcp;
        }
    }

    EMIT_LOAD_CT_MAP_FD_FIXUP(program, BPF_REG_1, tcp_map);

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

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                                  _BF_CT_RUNTIME_OFF(ct_state)));
        {
            _clean_bf_jmpctx_ struct bf_jmpctx not_new =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1,
                                                    CT_STATE_NEW, 0));

            {
                _clean_bf_jmpctx_ struct bf_jmpctx not_tcp =
                    bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8,
                                                         IPPROTO_TCP, 0));

                {
                    _clean_bf_jmpctx_ struct bf_jmpctx not_sctp =
                        bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8,
                                                           IPPROTO_SCTP, 0));

                    return 0;
                }

                r = _bf_ct_emit_entry_lookup(program);
                if (r)
                    return r;

                {
                    _clean_bf_jmpctx_ struct bf_jmpctx miss =
                        bf_jmpctx_get(program,
                                      BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

                    return 0;
                }

                return _bf_ct_emit_sctp_update(program);
            }

            r = _bf_ct_emit_entry_lookup(program);
            if (r)
                return r;

            {
                _clean_bf_jmpctx_ struct bf_jmpctx miss =
                    bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

                return 0;
            }

            return _bf_ct_emit_tcp_update(program);
        }
    }

    return 0;
}

static int _bf_ct_emit_create(struct bf_program *program)
{
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_SCR_OFF(0), 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, _BF_CT_RUNTIME_OFF(ct_maps)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v4)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(8)));

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                                _BF_CT_RUNTIME_OFF(ct_key_v6)));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(16)));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_state)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(24)));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_is_v6)));
    EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(25)));

    _bf_ct_emit_runtime_reg(program, BPF_REG_1);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_CT_CREATE);

    return 0;
}

int bf_ct_emit_create_if_new(struct bf_program *program, bool notrack)
{
    if (!bf_program_chain_uses_ct(program))
        return 0;

    if (notrack)
        return 0;

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_hairpin_skip)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx skip =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 0));

        (void)skip;
    }

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10,
                              _BF_CT_RUNTIME_OFF(ct_state)));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx not_new =
            bf_jmpctx_get(program,
                          BPF_JMP_IMM(BPF_JNE, BPF_REG_1, CT_STATE_NEW, 0));

        (void)not_new;
    }

    return _bf_ct_emit_create(program);
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
