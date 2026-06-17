/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bfc_opts;

int bfc_ct_gc_sweep(const struct bfc_opts *opts);
int bfc_ct_gc_run(const struct bfc_opts *opts);
int bfc_ct_gc_status(const struct bfc_opts *opts);
