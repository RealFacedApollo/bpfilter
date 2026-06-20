/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file ct.h
 *
 * Conntrack data structures and map lifecycle for stateful filtering.
 *
 * Shared between userspace map management and future BPF datapath stubs.
 * Layouts must remain stable across both contexts.
 */

#define BF_CT_NS_PER_S 1000000000ULL

/* Rule-visible connection states (Phase 3). */
#define CT_STATE_NEW (1u << 0)
#define CT_STATE_ESTABLISHED (1u << 1)
#define CT_STATE_RELATED (1u << 2)
#define CT_STATE_INVALID (1u << 3)
#define CT_STATE_REPLY (1u << 4)

/* Internal ct_entry flags. */
#define CT_FLAG_SEEN_REPLY (1u << 0)
#define CT_FLAG_ASSURED (1u << 1)
#define CT_FLAG_DYING (1u << 2)
#define CT_FLAG_INVALID (1u << 3)
#define CT_FLAG_RELATED (1u << 4)
#define CT_FLAG_NOTRACK (1u << 5)

#define BF_CT_MAP_TCP_MAX 524288u
#define BF_CT_MAP_TCP6_MAX 262144u
#define BF_CT_MAP_ANY_MAX 524288u
#define BF_CT_MAP_ANY6_MAX 262144u
#define BF_CT_SRC_RATE_MAX 65536u
#define BF_CT_SRC_COUNT_MAX 65536u
#define BF_CT_MAP_SPI_REVERSE_MAX 65536u

#define CT_RATE_LIMIT_TCP 100u
#define CT_RATE_LIMIT_UDP 50u
#define CT_RATE_LIMIT_ICMP 20u
#define CT_RATE_LIMIT_OTHER 20u
#define CT_RATE_WINDOW_NS BF_CT_NS_PER_S

#define CT_MAX_ENTRIES_PER_SRC_TCP 1000u
#define CT_MAX_ENTRIES_PER_SRC_UDP 500u
#define CT_MAX_ENTRIES_PER_SRC_OTHER 200u

#define BF_CT_PIN_DIR "ct"

struct bf_chain;

/** Internal TCP FSM states (§7.2). */
enum ct_tcp_state
{
    CT_TCP_NONE = 0,
    CT_TCP_SYN_SENT = 1,
    CT_TCP_SYN_RECV = 2,
    CT_TCP_ESTABLISHED = 3,
    CT_TCP_FIN_WAIT = 4,
    CT_TCP_TIME_WAIT = 5,
    CT_TCP_CLOSE = 6,
};

/** Internal SCTP FSM states (§7.3). */
enum ct_sctp_state
{
    CT_SCTP_NONE = 0,
    CT_SCTP_INIT = 1,
    CT_SCTP_INIT_ACK = 2,
    CT_SCTP_ESTABLISHED = 3,
    CT_SCTP_SHUTDOWN = 4,
    CT_SCTP_CLOSE = 5,
};

/**
 * Universal connection key — 16 bytes for IPv4, 40 bytes for IPv6.
 */
struct ct_key_v4
{
    __be32 lo_ip;
    __be32 hi_ip;
    __u32 discriminator;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

struct ct_key_v6
{
    struct in6_addr lo_ip;
    struct in6_addr hi_ip;
    __u32 discriminator;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

/**
 * Unified connection entry — 64 bytes for all protocols.
 *
 * @note For IPv6 flows, @c orig_src_ip and @c orig_dst_ip hold only the first
 *       four bytes of the 16-byte address. Full addresses live in @c ct_key_v6.
 */
struct ct_entry
{
    __u64 last_seen_ns;
    __u64 created_ns;

    __u32 rx_packets;
    __u32 tx_packets;
    __u32 rx_bytes;
    __u32 tx_bytes;

    __u8 proto;
    __u8 flags;
    __u8 internal_state;
    __u8 orig_lo_is_src;

    __u32 orig_discriminator;
    __u32 reply_discriminator;

    __be32 orig_src_ip;
    __be32 orig_dst_ip;

    __u8 _pad[12];
} __attribute__((packed));

struct ct_rate_entry
{
    __u64 window_start_ns;
    __u32 pkt_count;
    __u32 _pad;
} __attribute__((packed));

struct ct_src_count_entry
{
    __u32 count;
    __u32 _pad;
} __attribute__((packed));

struct ct_timeouts
{
    __u64 tcp_syn_ns;
    __u64 tcp_established_ns;
    __u64 tcp_fin_wait_ns;
    __u64 tcp_time_wait_ns;
    __u64 tcp_close_ns;
    __u64 udp_new_ns;
    __u64 udp_established_ns;
    __u64 icmp_ns;
    __u64 sctp_init_ns;
    __u64 sctp_established_ns;
    __u64 sctp_shutdown_ns;
    __u64 ipsec_ns;
    __u64 gre_ns;
    __u64 generic_ns;
} __attribute__((packed));

struct ct_stats_counters
{
    __u64 new_tcp;
    __u64 new_udp;
    __u64 new_icmp;
    __u64 new_other;
    __u64 established;
    __u64 related;
    __u64 invalid;
    __u64 dropped_rate_limit;
    __u64 dropped_src_count;
    __u64 ringbuf_drops;
    __u64 gc_phase1_marked;
    __u64 gc_phase2_deleted;
} __attribute__((packed));

/**
 * Source-IP key for rate and count maps. IPv4 addresses are stored as
 * IPv4-mapped IPv6 (::ffff:0:0/96 + v4).
 */
struct ct_ip_key
{
    struct in6_addr addr;
} __attribute__((packed));

/** ESP/AH reverse SPI lookup key (§12.6). */
struct ct_spi_reverse_key
{
    __be32 lo_ip;
    __be32 hi_ip;
    __u32 reply_spi;
    __u8 proto;
    __u8 pad[3];
} __attribute__((packed));

/**
 * Parsed packet fields shared by the conntrack BPF subprograms.
 *
 * @warning This struct is staged in the per-CPU @ref ct_subprog_scratch map, so
 *          it must remain free of pointer fields: the BPF verifier rejects
 *          storing a packet/stack/map pointer into map-value memory. Transport
 *          header data needed after parsing (e.g. the TCP flags) is copied into
 *          scalar fields here instead of keeping the header pointer.
 */
struct bf_ct_pkt_info
{
    __u8 is_v6;
    __u8 proto;
    __u16 sport;
    __u16 dport;
    __u8 icmp_type;
    __u16 icmp_id;
    __u32 spi;
    __u32 gre_key;
    __u8 sctp_chunk;
    /** Non-zero once an L4 header has been parsed for this packet. */
    __u8 has_l4;
    /** TCP flag bits, valid when @c proto is TCP and @c has_l4 is set. */
    __u8 tcp_syn;
    __u8 tcp_ack;
    __u8 tcp_rst;
    __u8 tcp_fin;
    __be32 src_v4;
    __be32 dst_v4;
    struct in6_addr src_v6;
    struct in6_addr dst_v6;
};

/**
 * Per-CPU scratch for the conntrack BPF subprograms (§10.5).
 *
 * The CT lookup/create stubs run as BPF-to-BPF subprograms, whose stack frame
 * stacks on top of the calling program's. To stay within the 512-byte combined
 * stack budget, their largest working structures live here, in a host-global
 * single-entry per-CPU array, instead of on the subprogram stack. Only one CT
 * subprogram runs per packet on a given CPU, so a single slot is sufficient.
 */
struct ct_subprog_scratch
{
    struct bf_ct_pkt_info pkt;
    struct ct_entry entry;
};

/**
 * Per-CPU scratch for conntrack state across tail-call segments (§10.5).
 */
struct ct_tail_scratch
{
    __u8 ct_state;
    __u8 is_reply;
    __u8 ct_state_valid;
    __u8 is_v6;
    union {
        struct ct_key_v4 key_v4;
        struct ct_key_v6 key_v6;
    };
} __attribute__((packed));

/**
 * Userspace-owned conntrack metadata (key-norm version, GC heartbeat).
 */
struct ct_meta
{
    __u32 key_norm_version;
    __u64 last_sweep_ns;
    __u32 _pad;
} __attribute__((packed));

#define BF_CT_KEY_NORM_VERSION 1u
#define BF_CT_GC_STALE_THRESHOLD_NS (120ULL * BF_CT_NS_PER_S)

/** Hairpin guard slot in @c sk_buff->cb (§11.3). */
#define BF_CT_CB_SLOT 0
#define BF_CT_CB_PROCESSED 0x5au

/**
 * Arguments for @c bf_ct_lookup() — keeps the stub within five BPF registers.
 *
 * @note The CT maps are referenced by the stubs as host-global relocatable
 *       globals (see ct/bpf/maps.h), so no map pointer is passed here.
 */
struct bf_ct_lookup_args
{
    struct ct_key_v4 *key_v4;
    struct ct_key_v6 *key_v6;
    __u8 *is_reply;
};

/** Arguments for @c bf_ct_create_if_new(). */
struct bf_ct_create_args
{
    struct ct_key_v4 *key_v4;
    struct ct_key_v6 *key_v6;
    __u8 ct_state;
    __u8 is_v6;
    __u8 pad[6];
};

enum bf_ct_map_id
{
    BF_CT_MAP_TCP,
    BF_CT_MAP_TCP6,
    BF_CT_MAP_ANY,
    BF_CT_MAP_ANY6,
    BF_CT_MAP_SRC_RATE,
    BF_CT_MAP_SRC_COUNT,
    BF_CT_MAP_SPI_REVERSE,
    BF_CT_MAP_TIMEOUTS,
    BF_CT_MAP_STATS,
    BF_CT_MAP_TAIL_SCRATCH,
    BF_CT_MAP_META,
    BF_CT_MAP_SUBPROG_SCRATCH,

    _BF_CT_MAP_MAX,
};

struct bf_ct_maps;
struct bf_ct_maps_opts;

#ifdef __cplusplus
static_assert(sizeof(struct ct_key_v4) == 16);
static_assert(sizeof(struct ct_key_v6) == 40);
static_assert(sizeof(struct ct_entry) == 64);
static_assert(sizeof(struct ct_rate_entry) == 16);
static_assert(sizeof(struct ct_src_count_entry) == 8);
static_assert(sizeof(struct ct_timeouts) == 112);
static_assert(sizeof(struct ct_stats_counters) == 96);
static_assert(sizeof(struct ct_ip_key) == 16);
static_assert(sizeof(struct ct_spi_reverse_key) == 16);
static_assert(sizeof(struct ct_tail_scratch) == 44);
static_assert(sizeof(struct ct_meta) == 16);
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct ct_key_v4) == 16, "ct_key_v4 must be 16 bytes");
_Static_assert(sizeof(struct ct_key_v6) == 40, "ct_key_v6 must be 40 bytes");
_Static_assert(sizeof(struct ct_entry) == 64, "ct_entry must be 64 bytes");
_Static_assert(sizeof(struct ct_rate_entry) == 16, "ct_rate_entry must be 16 bytes");
_Static_assert(sizeof(struct ct_src_count_entry) == 8,
               "ct_src_count_entry must be 8 bytes");
_Static_assert(sizeof(struct ct_timeouts) == 112, "ct_timeouts must be 112 bytes");
_Static_assert(sizeof(struct ct_stats_counters) == 96,
               "ct_stats_counters must be 96 bytes");
_Static_assert(sizeof(struct ct_ip_key) == 16, "ct_ip_key must be 16 bytes");
_Static_assert(sizeof(struct ct_spi_reverse_key) == 16,
               "ct_spi_reverse_key must be 16 bytes");
_Static_assert(sizeof(struct ct_tail_scratch) == 44,
               "ct_tail_scratch must be 44 bytes");
_Static_assert(sizeof(struct ct_meta) == 16, "ct_meta must be 16 bytes");
#endif

#define _free_bf_ct_maps_ __attribute__((__cleanup__(bf_ct_maps_free)))

/**
 * @brief Optional sizing overrides. Zero fields select design defaults.
 */
struct bf_ct_maps_opts
{
    uint32_t max_tcp;
    uint32_t max_tcp6;
    uint32_t max_any;
    uint32_t max_any6;
    uint32_t max_src_rate;
    uint32_t max_src_count;
    uint32_t max_spi_reverse;
};

/**
 * @brief Build a protocol-specific discriminator from packet fields.
 *
 * @param proto IP protocol number.
 * @param sport Source port (TCP/UDP/SCTP) or 0.
 * @param dport Destination port (TCP/UDP/SCTP) or 0.
 * @param icmp_id ICMP/ICMPv6 echo identifier or 0.
 * @param spi ESP/AH SPI or 0.
 * @param gre_key GRE key or 0.
 * @param swapped If true, @p src was the larger IP after normalization.
 * @return Encoded discriminator for @ref ct_key_v4 or @ref ct_key_v6.
 */
__u32 bf_ct_build_discriminator(__u8 proto, __u16 sport, __u16 dport,
                               __u16 icmp_id, __u32 spi, __u32 gre_key,
                               bool swapped);

/**
 * @brief Normalize IPv4 addresses and discriminators into a canonical key.
 *
 * @param src Source address from the packet.
 * @param dst Destination address from the packet.
 * @param src_disc Source-side discriminator (sport, echo_id, SPI, ...).
 * @param dst_disc Destination-side discriminator (dport when applicable).
 * @param proto IP protocol number.
 * @param key Output normalized key. Can't be NULL.
 * @param orig_lo_is_src Set to 1 if the packet source equals @c key->lo_ip.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ct_key_normalize_v4(__be32 src, __be32 dst, __u32 src_disc,
                           __u32 dst_disc, __u8 proto, struct ct_key_v4 *key,
                           bool *orig_lo_is_src);

/**
 * @brief Normalize IPv6 addresses and discriminators into a canonical key.
 */
int bf_ct_key_normalize_v6(const struct in6_addr *src,
                           const struct in6_addr *dst, __u32 src_disc,
                           __u32 dst_disc, __u8 proto, struct ct_key_v6 *key,
                           bool *orig_lo_is_src);

/**
 * @brief Encode an IPv4 address as an IPv4-mapped IPv6 @ref ct_ip_key.
 */
void bf_ct_ip_key_from_v4(__be32 addr, struct ct_ip_key *key);

/**
 * @brief Copy a native IPv6 address into @ref ct_ip_key.
 */
void bf_ct_ip_key_from_v6(const struct in6_addr *addr, struct ct_ip_key *key);

/**
 * @brief Fill @p timeouts with design-default values (§21.D).
 */
void bf_ct_timeouts_defaults(struct ct_timeouts *timeouts);

/**
 * @brief Select the expiry timeout for @p e from @p t (§14.2).
 */
__u64 bf_ct_get_timeout_ns(const struct ct_entry *e,
                             const struct ct_timeouts *t);

/**
 * @brief Reject conntrack chains attached to incompatible hooks (§5.2).
 *
 * @param chain Chain to validate. Can't be NULL.
 * @return 0 on success, or @c -ENOTSUP when the hook cannot support CT.
 */
int bf_ct_validate_hook_compat(const struct bf_chain *chain);

/**
 * @brief Report whether a chain consults connection state.
 *
 * A chain "consumes" conntrack when at least one enabled rule carries a
 * @c ct.conntrack matcher. This is the trigger for lazily creating the
 * host-global conntrack maps: chains that merely accept traffic (and would
 * implicitly create entries) do not arm conntrack on their own.
 *
 * @param chain Chain to inspect. Can't be NULL.
 * @return true if the chain reads connection state, false otherwise.
 */
bool bf_ct_chain_consumes_ct(const struct bf_chain *chain);

/**
 * @brief Emit load-time warnings for common conntrack policy mistakes (§18.1).
 *
 * @param chain Chain to inspect. Can't be NULL.
 */
void bf_ct_warn_chain_policy(const struct bf_chain *chain);

/**
 * @brief Parse @c MemAvailable from a @c /proc/meminfo buffer.
 *
 * @param meminfo Meminfo text. Can't be NULL.
 * @param out_kb Parsed value in kB. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ct_parse_mem_available_kb(const char *meminfo, uint64_t *out_kb);

/**
 * @brief Estimate pinned conntrack map memory from sizing options.
 *
 * @param opts Sizing overrides, or NULL for defaults.
 * @return Estimated bytes for flow and side maps.
 */
uint64_t bf_ct_estimate_map_bytes(const struct bf_ct_maps_opts *opts);

/**
 * @brief Warn when CT map sizing may exhaust host memory (§18.1.4).
 *
 * @param opts Sizing overrides, or NULL for defaults.
 */
void bf_ct_warn_map_memory(const struct bf_ct_maps_opts *opts);

/**
 * @brief Clamp timeout values to supported bounds and log changes (§18.1.5).
 *
 * @param timeouts Timeout table to clamp in place. Can't be NULL.
 */
void bf_ct_timeouts_clamp(struct ct_timeouts *timeouts);

#define BF_CT_GC_BATCH_SIZE 10000u
#define BF_CT_GC_INTERVAL_SEC 10u

/**
 * @brief GC sweep options.
 */
struct bf_ct_gc_opts
{
    /** Maximum entries to process per flow map per batch. */
    unsigned batch_size;
    /** When true, skip maps that finished iteration (for @c sweep_full). */
    bool track_completion;
};

/**
 * @brief Persistent iteration state for batched GC sweeps.
 */
struct bf_ct_gc
{
    struct ct_key_v4 cursor_v4[2];
    struct ct_key_v6 cursor_v6[2];
    bool cursor_valid[4];
    bool map_completed[4];
};

/**
 * @brief Reset GC iteration cursors.
 */
void bf_ct_gc_init(struct bf_ct_gc *gc);

/**
 * @brief Sweep up to @p opts->batch_size entries in each flow map once.
 */
int bf_ct_gc_sweep_batch(const struct bf_ct_maps *maps, struct bf_ct_gc *gc,
                         const struct bf_ct_gc_opts *opts);

/**
 * @brief Sweep all flow maps until every entry has been visited once.
 */
int bf_ct_gc_sweep_full(const struct bf_ct_maps *maps, struct bf_ct_gc *gc,
                        const struct bf_ct_gc_opts *opts);

/**
 * @brief Create conntrack maps and pin them under @c pindir_fd/ct/.
 *
 * Reopens existing pinned maps when present.
 *
 * @param maps Output map set. Can't be NULL.
 * @param pindir_fd File descriptor for @c $BPFFS/bpfilter/.
 * @param opts Sizing overrides, or NULL for defaults.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ct_maps_init(struct bf_ct_maps **maps, int pindir_fd,
                    const struct bf_ct_maps_opts *opts);

/**
 * @brief Reopen pinned conntrack maps from @c pindir_fd/ct/.
 */
int bf_ct_maps_open(struct bf_ct_maps **maps, int pindir_fd);

/**
 * @brief Report whether conntrack maps are already pinned on the host.
 *
 * Probes @c pindir_fd/ct/ without creating the directory or any map, so it is
 * safe to call before deciding whether to allocate the maps.
 *
 * @param pindir_fd File descriptor for @c $BPFFS/bpfilter/.
 * @return true if the pinned maps exist, false otherwise.
 */
bool bf_ct_maps_exist(int pindir_fd);

/**
 * @brief Release map file descriptors.
 */
void bf_ct_maps_free(struct bf_ct_maps **maps);

/**
 * @brief Pin all maps into @c pindir_fd/ct/.
 */
int bf_ct_maps_pin(const struct bf_ct_maps *maps, int pindir_fd);

/**
 * @brief Return a map file descriptor.
 */
int bf_ct_maps_get_fd(const struct bf_ct_maps *maps, enum bf_ct_map_id id);

/**
 * @brief Resolve a CT map ELF symbol name to its @ref bf_ct_map_id.
 *
 * The conntrack BPF stubs reference the host-global CT maps as relocatable
 * globals (e.g. @c bf_ct_map_tcp). When an ELF stub is loaded, the elfstub
 * relocation pass uses this mapping to turn each map symbol into a
 * @c BF_FIXUP_TYPE_CT_MAP_FD fixup, so the real pinned map fd is patched into
 * the @c BPF_LD_MAP_FD instruction.
 *
 * @param name Symbol name of the map, as found in the stub's symbol table.
 * @return The matching @ref bf_ct_map_id (>= 0), or @c -ENOENT if @p name is
 *         not a known CT map symbol.
 */
int bf_ct_map_id_from_sym(const char *name);

/**
 * @brief Write default timeout values into the @c ct_timeouts map.
 */
int bf_ct_maps_init_timeouts(struct bf_ct_maps *maps);

/**
 * @brief Initialize or upgrade the @c ct_meta map.
 */
int bf_ct_maps_init_meta(struct bf_ct_maps *maps);

/**
 * @brief Reject program reload when pinned CT maps use a different key-norm
 *        version than this build expects.
 */
int bf_ct_maps_check_reload(const struct bf_ct_maps *maps);

/**
 * @brief Read the @c ct_meta singleton.
 */
int bf_ct_meta_get(struct ct_meta *out, const struct bf_ct_maps *maps);

/**
 * @brief Record the timestamp of the latest GC sweep batch.
 */
int bf_ct_meta_set_last_sweep_ns(const struct bf_ct_maps *maps, __u64 ns);
