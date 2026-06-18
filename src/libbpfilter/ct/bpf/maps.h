/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>

#include "ct/bpf/helpers.h"

/**
 * @file maps.h
 *
 * Host-global conntrack maps, referenced by the CT BPF stubs as relocatable
 * globals. This is the verifier-native way to access a map: the reference is a
 * `BPF_LD_MAP_FD` instruction materialized from a relocation at each use site,
 * so the map keeps its `CONST_PTR_TO_MAP` type regardless of the call frame.
 *
 * The maps below are never created from these definitions: the real pinned,
 * host-global maps are created in userspace (see @ref bf_ct_maps_init), and the
 * elfstub loader patches each `BPF_LD_MAP_FD` immediate with the real fd
 * (matching the symbol name through @ref bf_ct_map_id_from_sym). The
 * definitions exist only so clang emits the relocations; their type, size and
 * flags are irrelevant to the integrated stub.
 *
 * When the same headers are loaded as a standalone BPF program (the conntrack
 * unit-test harness, loaded by libbpf), libbpf performs the relocation itself
 * and these become the program's actual maps.
 */

#if defined(BF_CT_BPF_WITH_LIBBPF_HELPERS)

#ifndef BF_CT_BPF_FLOW_MAP_MAX
#define BF_CT_BPF_FLOW_MAP_MAX 4096u
#endif

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BF_CT_BPF_FLOW_MAP_MAX);
    __type(key, struct ct_key_v4);
    __type(value, struct ct_entry);
} bf_ct_map_tcp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BF_CT_BPF_FLOW_MAP_MAX);
    __type(key, struct ct_key_v6);
    __type(value, struct ct_entry);
} bf_ct_map_tcp6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BF_CT_BPF_FLOW_MAP_MAX);
    __type(key, struct ct_key_v4);
    __type(value, struct ct_entry);
} bf_ct_map_any SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BF_CT_BPF_FLOW_MAP_MAX);
    __type(key, struct ct_key_v6);
    __type(value, struct ct_entry);
} bf_ct_map_any6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BF_CT_BPF_FLOW_MAP_MAX);
    __type(key, struct ct_spi_reverse_key);
    __type(value, __u32);
} bf_ct_map_spi_reverse SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ct_stats_counters);
} bf_ct_map_stats SEC(".maps");

/**
 * @brief Select the flow-table map for a packet, by relocation.
 *
 * Each branch returns the address of a global map, so clang emits a
 * `BPF_LD_MAP_FD` per candidate. The verifier tracks the selected pointer as a
 * map pointer because it traces back to those relocation constants — never to
 * stack memory.
 *
 * @param is_v6 Non-zero for the IPv6 flow tables.
 * @param proto L4 protocol; TCP uses the dedicated table, everything else the
 *        "any" table.
 * @return Address of the selected flow map.
 */
static __always_inline void *bf_ct_bpf_flow_map_global(__u8 is_v6, __u8 proto)
{
    if (proto == IPPROTO_TCP)
        return is_v6 ? (void *)&bf_ct_map_tcp6 : (void *)&bf_ct_map_tcp;
    return is_v6 ? (void *)&bf_ct_map_any6 : (void *)&bf_ct_map_any;
}

#endif /* BF_CT_BPF_WITH_LIBBPF_HELPERS */
