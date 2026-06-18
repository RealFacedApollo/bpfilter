// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/core/list.h>
#include <bpfilter/core/vector.h>
#include <bpfilter/chain.h>
#include <bpfilter/ctx.h>
#include <bpfilter/ct.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>

#include <linux/bpf.h>

#include <unistd.h>

#include "cgen/fixup.h"
#include "cgen/ct.h"
#include "cgen/handle.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "core/lock.h"
#include "mock.h"
#include "test.h"

static void _bft_require_bpffs(void)
{
    if (access("/sys/fs/bpf", F_OK) != 0)
        skip();
}

static void _bft_ctx_setup_ct_or_skip(void)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    int r;

    _bft_require_bpffs();
    bf_ctx_teardown();
    r = bf_ctx_setup_ex(false, "/sys/fs/bpf", 0, BF_CTX_F_CONNTRACK);
    if (r)
        skip();

    // Conntrack maps are created lazily; arm them explicitly so the code
    // generator emits the conntrack datapath for these codegen tests.
    if (bf_lock_init(&lock, BF_LOCK_WRITE))
        skip();
    if (bf_ctx_ensure_ct_maps(lock.pindir_fd))
        skip();
}

static ssize_t _bft_ct_lookup_call_insn(const struct bf_program *program)
{
    size_t stub = program->elfstubs_location[BF_ELFSTUB_CT_LOOKUP];
    size_t i;

    if (!stub)
        return -1;

    for (i = 0; i < program->img.size; ++i) {
        const struct bpf_insn *insn = bf_vector_get(&program->img, i);

        if (BPF_CLASS(insn->code) == BPF_JMP &&
            BPF_OP(insn->code) == BPF_CALL &&
            insn->src_reg == BPF_PSEUDO_CALL &&
            (size_t)((ssize_t)i + 1 + insn->imm) == stub)
            return (ssize_t)i;
    }

    return -1;
}

static bool _bft_ct_has_jmp_between(const struct bf_program *program,
                                    ssize_t from, ssize_t to)
{
    ssize_t i;

    if (from < 0 || to < 0 || from >= to)
        return false;

    for (i = from + 1; i < to; ++i) {
        const struct bpf_insn *insn = bf_vector_get(&program->img, (size_t)i);

        if (BPF_CLASS(insn->code) != BPF_JMP ||
            BPF_OP(insn->code) == BPF_CALL)
            continue;

        return true;
    }

    return false;
}

static ssize_t _bft_ct_insn_find_st_u8(const struct bf_program *program, int dst,
                                       int off, int imm)
{
    size_t i;

    for (i = 0; i < program->img.size; ++i) {
        const struct bpf_insn *insn = bf_vector_get(&program->img, i);

        if (insn->code == (BPF_ST | BPF_MEM | BPF_B) && insn->dst_reg == dst &&
            insn->off == off && insn->imm == imm)
            return (ssize_t)i;
    }

    return -1;
}

static bool _bft_ct_has_tail_scratch_invalidate(const struct bf_program *program)
{
    bf_list_node *node;
    bool has_map = false;
    bool has_zero = false;

    bf_list_foreach (&program->fixups, node) {
        struct bf_fixup *fixup = bf_list_node_get_data(node);

        if (fixup->type == BF_FIXUP_TYPE_CT_MAP_FD &&
            fixup->attr.ct_map_id == BF_CT_MAP_TAIL_SCRATCH)
            has_map = true;
    }

    if (_bft_ct_insn_find_st_u8(
            program, BPF_REG_0,
            (int)offsetof(struct ct_tail_scratch, ct_state_valid), 0) >= 0)
        has_zero = true;

    return has_map && has_zero;
}

static int _bft_ct_chain_new(struct bf_chain **chain, bool ct_matcher,
                             bool notrack_accept)
{
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    struct bf_match_ct_payload ct = {
        .state_mask = CT_STATE_ESTABLISHED | CT_STATE_RELATED,
    };
    uint16_t dport = htobe16(443);
    int r;

    if (ct_matcher) {
        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                      &ct, sizeof(ct), false));
        rule->verdict = BF_VERDICT_DROP;
        assert_ok(bf_list_add_tail(&rules, rule));
    }

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                  &dport, sizeof(dport), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    if (notrack_accept)
        rule->flags |= BF_RULE_F_NOTRACK;
    assert_ok(bf_list_add_tail(&rules, rule));

    r = bf_chain_new(chain, "ct_codegen", BF_HOOK_TC_INGRESS, BF_VERDICT_DROP,
                     NULL, &rules);
    if (r)
        return r;

    return 0;
}

static int _bft_ct_chain_new_n_rules(struct bf_chain **chain, size_t filler_rules)
{
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *rule = NULL;
    struct bf_match_ct_payload ct = {
        .state_mask = CT_STATE_ESTABLISHED | CT_STATE_RELATED,
    };
    uint16_t accept_port = htobe16(443);
    size_t i;

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_CONNTRACK, BF_MATCHER_EQ,
                                  &ct, sizeof(ct), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    for (i = 0; i < filler_rules; ++i) {
        uint16_t dport = htobe16((uint16_t)(10000 + i));

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                      &dport, sizeof(dport), false));
        rule->verdict = BF_VERDICT_DROP;
        assert_ok(bf_list_add_tail(&rules, rule));
    }

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                  &accept_port, sizeof(accept_port), false));
    rule->verdict = BF_VERDICT_ACCEPT;
    assert_ok(bf_list_add_tail(&rules, rule));

    return bf_chain_new(chain, "ct_split", BF_HOOK_TC_INGRESS, BF_VERDICT_DROP,
                        NULL, &rules);
}

static bool _bft_ct_has_prog_array_fixup(const struct bf_program *program)
{
    bf_list_node *node;

    bf_list_foreach (&program->fixups, node) {
        struct bf_fixup *fixup = bf_list_node_get_data(node);

        if (fixup->type == BF_FIXUP_TYPE_PROG_ARRAY_FD)
            return true;
    }

    return false;
}

static void large_ct_chain_splits_into_segments(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;
    size_t filler;
    size_t last_insn_count;
    uint32_t last_segments;
    bool split;

    (void)state;

    _bft_ctx_setup_ct_or_skip();

    split = false;
    last_insn_count = 0;
    last_segments = 1;

    for (filler = 32; filler <= 512; filler *= 2) {
        assert_ok(_bft_ct_chain_new_n_rules(&chain, filler));
        assert_true(chain->flags & BF_FLAG(BF_CHAIN_CONNTRACK));

        assert_ok(bf_handle_new(&handle, "bf_prog"));
        assert_ok(bf_program_new(&program, chain, handle));
        assert_ok(bf_program_generate_split(program));

        last_insn_count = program->img.size;
        last_segments = program->handle->n_segments;

        if (program->handle->n_segments > 1) {
            split = true;
            break;
        }

        bf_program_free(&program);
        bf_handle_free(&handle);
        bf_chain_free(&chain);
    }

    if (!split) {
        fail_msg("expected tail-call split (last insns=%zu segments=%u)",
                 last_insn_count, last_segments);
    }

    assert_true(program->img.size > 0);
    assert_true(_bft_ct_has_prog_array_fixup(program));

    bf_ctx_teardown();
}

static void codegen_skips_ct_without_maps(void **state)
{
    _free_bft_tmpdir_ struct bft_tmpdir *tmpdir = NULL;
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;

    (void)state;

    assert_ok(bft_tmpdir_new(&tmpdir));
    assert_ok(bf_ctx_setup(false, tmpdir->dir_path, 0));

    assert_ok(_bft_ct_chain_new(&chain, true, false));
    assert_true(chain->flags & BF_FLAG(BF_CHAIN_CONNTRACK));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));

    assert_int_equal(program->elfstubs_location[BF_ELFSTUB_CT_LOOKUP], 0);
    assert_int_equal(program->elfstubs_location[BF_ELFSTUB_CT_CREATE], 0);

    bf_ctx_teardown();
}

static void codegen_emits_ct_with_maps(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_ct_chain_new(&chain, true, false));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));

    assert_true(program->elfstubs_location[BF_ELFSTUB_CT_LOOKUP] > 0);
    assert_true(program->elfstubs_location[BF_ELFSTUB_CT_CREATE] > 0);
    assert_true(program->img.size > 0);
    assert_int_equal(program->handle->n_segments, 1);

    bf_ctx_teardown();
}

static void codegen_notrack_skips_create_stub(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_ct_chain_new(&chain, true, true));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));

    assert_true(program->elfstubs_location[BF_ELFSTUB_CT_LOOKUP] > 0);
    assert_int_equal(program->elfstubs_location[BF_ELFSTUB_CT_CREATE], 0);

    bf_ctx_teardown();
}

static void hairpin_first_visit_preserves_lookup(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;
    ssize_t lookup_insn;
    ssize_t hairpin_skip_insn;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_ct_chain_new(&chain, true, false));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    assert_ok(bf_program_generate_split(program));

    lookup_insn = _bft_ct_lookup_call_insn(program);
    hairpin_skip_insn = _bft_ct_insn_find_st_u8(
        program, BPF_REG_10, BF_PROG_CTX_OFF(ct_hairpin_skip), 1);

    assert_true(lookup_insn >= 0);
    assert_true(hairpin_skip_insn >= 0);
    assert_true(lookup_insn < hairpin_skip_insn);
    assert_true(_bft_ct_has_jmp_between(program, lookup_insn,
                                        hairpin_skip_insn));

    bf_ctx_teardown();
}

static void segment_n_hairpin_invalidates_scratch(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_handle_ struct bf_handle *handle = NULL;
    _free_bf_program_ struct bf_program *program = NULL;

    (void)state;

    _bft_ctx_setup_ct_or_skip();
    assert_ok(_bft_ct_chain_new(&chain, true, false));

    assert_ok(bf_handle_new(&handle, "bf_prog"));
    assert_ok(bf_program_new(&program, chain, handle));
    program->ctgen.segment_idx = 1;
    program->ctgen.segment_total = 2;
    assert_ok(bf_program_generate(program));

    assert_true(_bft_ct_has_tail_scratch_invalidate(program));

    bf_ctx_teardown();
}

static int _bft_ct_tests_teardown(void **state)
{
    (void)state;
    bf_ctx_teardown();

    return 0;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(codegen_skips_ct_without_maps),
        cmocka_unit_test(codegen_emits_ct_with_maps),
        cmocka_unit_test(large_ct_chain_splits_into_segments),
        cmocka_unit_test(codegen_notrack_skips_create_stub),
        cmocka_unit_test(hairpin_first_visit_preserves_lookup),
        cmocka_unit_test(segment_n_hairpin_invalidates_scratch),
    };

    return cmocka_run_group_tests(tests, NULL, _bft_ct_tests_teardown);
}
