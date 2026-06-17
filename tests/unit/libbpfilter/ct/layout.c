// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>
#include <bpfilter/runtime.h>

#include "test.h"

static void ct_struct_layout(void **state)
{
    (void)state;

    assert_int_equal(sizeof(struct ct_key_v4), 16);
    assert_int_equal(sizeof(struct ct_key_v6), 40);
    assert_int_equal(sizeof(struct ct_entry), 64);
    assert_int_equal(sizeof(struct ct_rate_entry), 16);
    assert_int_equal(sizeof(struct ct_src_count_entry), 8);
    assert_int_equal(sizeof(struct ct_timeouts), 112);
    assert_int_equal(sizeof(struct ct_stats_counters), 96);
    assert_int_equal(sizeof(struct ct_ip_key), 16);
    assert_int_equal(sizeof(struct ct_spi_reverse_key), 16);
    assert_int_equal(sizeof(struct ct_tail_scratch), 44);
    assert_int_equal(sizeof(struct ct_meta), 16);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ct_struct_layout),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
