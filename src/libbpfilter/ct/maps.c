// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/ct.h>

#include <linux/bpf.h>

#include <stdbool.h>
#include <bpf/btf.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpf_types.h>
#include <bpfilter/btf.h>
#include <bpfilter/ctx.h>
#include <bpfilter/helper.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>

#define _free_bf_btf_ __attribute__((__cleanup__(_bf_ct_btf_free)))

struct bf_ct_map
{
    enum bf_ct_map_id id;
    enum bf_bpf_map_type bpf_type;
    char name[BPF_OBJ_NAME_LEN];
    size_t key_size;
    size_t value_size;
    size_t n_elems;
    int fd;
};

struct bf_ct_maps
{
    struct bf_ct_map maps[_BF_CT_MAP_MAX];
    int ct_dir_fd;
};

static void _bf_ct_btf_free(struct bf_btf **btf);

static int _bf_ct_btf_new(struct bf_btf **btf)
{
    _free_bf_btf_ struct bf_btf *_btf = NULL;

    assert(btf);

    _btf = malloc(sizeof(*_btf));
    if (!_btf)
        return -ENOMEM;

    _btf->fd = -1;
    _btf->btf = btf__new_empty();
    if (!_btf->btf)
        return -errno;

    *btf = TAKE_PTR(_btf);

    return 0;
}

static void _bf_ct_btf_free(struct bf_btf **btf)
{
    assert(btf);

    if (!*btf)
        return;

    btf__free((*btf)->btf);
    closep(&(*btf)->fd);
    BF_FREEP(btf);
}

static int _bf_ct_btf_load(struct bf_btf *btf)
{
    union bpf_attr attr = {};
    const void *raw;
    int r;

    assert(btf);

    raw = btf__raw_data(btf->btf, &attr.btf_size);
    if (!raw)
        return bf_err_r(errno, "failed to request BTF raw data");

    r = bf_bpf_btf_load(raw, attr.btf_size, bf_ctx_token());
    if (r < 0)
        return r;

    btf->fd = r;

    return 0;
}

static struct bf_btf *_bf_ct_make_flow_btf(const char *key_name, size_t key_size,
                                           size_t value_size, bool is_v6)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int u8_id, u32_id, ip_id;
    /* Bit offsets of the key fields, matching struct ct_key_v4/v6. The IPv6
     * addresses are 16 bytes each, shifting the trailing fields. */
    int hi_off = is_v6 ? 128 : 32;
    int disc_off = is_v6 ? 256 : 64;
    int proto_off = is_v6 ? 288 : 96;
    int r;

    r = _bf_ct_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    u8_id = btf__add_int(kbtf, "u8", 1, 0);
    u32_id = btf__add_int(kbtf, "u32", 4, 0);
    /* lo_ip/hi_ip are __be32 for IPv4 and 16-byte addresses for IPv6. */
    ip_id = is_v6 ? btf__add_array(kbtf, u32_id, u8_id, 16) : u32_id;

    btf->key_type_id = btf__add_struct(kbtf, key_name, key_size);
    btf__add_field(kbtf, "lo_ip", ip_id, 0, 0);
    btf__add_field(kbtf, "hi_ip", ip_id, hi_off, 0);
    btf__add_field(kbtf, "discriminator", u32_id, disc_off, 0);
    btf__add_field(kbtf, "proto", u8_id, proto_off, 0);
    btf->value_type_id = btf__add_struct(kbtf, "ct_entry", value_size);

    r = _bf_ct_btf_load(btf);
    if (r) {
        bf_warn_r(r, "failed to load flow map BTF for %s, ignoring", key_name);
        return NULL;
    }

    return TAKE_PTR(btf);
}

static struct bf_btf *_bf_ct_make_ip_key_btf(const char *value_name,
                                            size_t value_size)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int r;

    r = _bf_ct_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    int u8_id = btf__add_int(kbtf, "u8", 1, 0);
    int addr_id = btf__add_array(kbtf, btf__add_int(kbtf, "u32", 4, 0), u8_id, 16);
    btf->key_type_id = btf__add_struct(kbtf, "ct_ip_key", sizeof(struct ct_ip_key));
    btf__add_field(kbtf, "addr", addr_id, 0, 0);
    btf->value_type_id = btf__add_struct(kbtf, value_name, value_size);

    r = _bf_ct_btf_load(btf);
    if (r) {
        bf_warn_r(r, "failed to load IP-key map BTF, ignoring");
        return NULL;
    }

    return TAKE_PTR(btf);
}

static struct bf_btf *_bf_ct_make_array_btf(const char *value_name,
                                           size_t value_size)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int r;

    r = _bf_ct_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    btf__add_int(kbtf, "u64", 8, 0);
    btf->key_type_id = btf__add_int(kbtf, "u32", 4, 0);
    btf->value_type_id = btf__add_struct(kbtf, value_name, value_size);

    r = _bf_ct_btf_load(btf);
    if (r) {
        bf_warn_r(r, "failed to load array map BTF, ignoring");
        return NULL;
    }

    return TAKE_PTR(btf);
}

static struct bf_btf *_bf_ct_make_spi_reverse_btf(void)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int r;

    r = _bf_ct_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    int u8_id = btf__add_int(kbtf, "u8", 1, 0);
    int u32_id = btf__add_int(kbtf, "u32", 4, 0);
    btf->key_type_id =
        btf__add_struct(kbtf, "ct_spi_reverse_key",
                        sizeof(struct ct_spi_reverse_key));
    btf__add_field(kbtf, "lo_ip", u32_id, 0, 0);
    btf__add_field(kbtf, "hi_ip", u32_id, 32, 0);
    btf__add_field(kbtf, "reply_spi", u32_id, 64, 0);
    btf__add_field(kbtf, "proto", u8_id, 96, 0);
    btf->value_type_id = u32_id;

    r = _bf_ct_btf_load(btf);
    if (r) {
        bf_warn_r(r, "failed to load SPI reverse map BTF, ignoring");
        return NULL;
    }

    return TAKE_PTR(btf);
}

static void _bf_ct_map_close(struct bf_ct_map *map)
{
    assert(map);

    closep(&map->fd);
}

static int _bf_ct_map_create(struct bf_ct_map *map, int ct_dir_fd, bool *created)
{
    _free_bf_btf_ struct bf_btf *btf = NULL;
    _cleanup_close_ int fd = -1;
    int r;

    assert(map);
    assert(created);

    *created = false;

    switch (map->id) {
    case BF_CT_MAP_TCP:
        btf = _bf_ct_make_flow_btf("ct_key_v4", sizeof(struct ct_key_v4),
                                   sizeof(struct ct_entry), false);
        break;
    case BF_CT_MAP_TCP6:
        btf = _bf_ct_make_flow_btf("ct_key_v6", sizeof(struct ct_key_v6),
                                   sizeof(struct ct_entry), true);
        break;
    case BF_CT_MAP_ANY:
        btf = _bf_ct_make_flow_btf("ct_key_v4", sizeof(struct ct_key_v4),
                                   sizeof(struct ct_entry), false);
        break;
    case BF_CT_MAP_ANY6:
        btf = _bf_ct_make_flow_btf("ct_key_v6", sizeof(struct ct_key_v6),
                                   sizeof(struct ct_entry), true);
        break;
    case BF_CT_MAP_SRC_RATE:
        btf = _bf_ct_make_ip_key_btf("ct_rate_entry", sizeof(struct ct_rate_entry));
        break;
    case BF_CT_MAP_SRC_COUNT:
        btf = _bf_ct_make_ip_key_btf("ct_src_count_entry",
                                     sizeof(struct ct_src_count_entry));
        break;
    case BF_CT_MAP_SPI_REVERSE:
        btf = _bf_ct_make_spi_reverse_btf();
        break;
    case BF_CT_MAP_TIMEOUTS:
        btf = _bf_ct_make_array_btf("ct_timeouts", sizeof(struct ct_timeouts));
        break;
    case BF_CT_MAP_STATS:
        btf = _bf_ct_make_array_btf("ct_stats_counters",
                                    sizeof(struct ct_stats_counters));
        break;
    case BF_CT_MAP_TAIL_SCRATCH:
        btf = _bf_ct_make_array_btf("ct_tail_scratch",
                                     sizeof(struct ct_tail_scratch));
        break;
    case BF_CT_MAP_META:
        btf = _bf_ct_make_array_btf("ct_meta", sizeof(struct ct_meta));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown conntrack map id %d", map->id);
    }

    r = bf_bpf_obj_get(map->name, ct_dir_fd, &fd);
    if (r == 0) {
        map->fd = TAKE_FD(fd);
        return 0;
    }
    if (r != -ENOENT)
        return bf_err_r(r, "failed to open pinned map '%s'", map->name);

    fd = bf_bpf_map_create(map->name, map->bpf_type, map->key_size,
                           map->value_size, map->n_elems, btf, bf_ctx_token());
    if (fd < 0)
        return bf_err_r(fd, "failed to create map '%s'", map->name);

    map->fd = TAKE_FD(fd);

    r = bf_bpf_obj_pin(map->name, map->fd, ct_dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin map '%s'", map->name);

    *created = true;

    return 0;
}

static void _bf_ct_map_init_def(struct bf_ct_map *map, enum bf_ct_map_id id,
                                enum bf_bpf_map_type bpf_type, const char *name,
                                size_t key_size, size_t value_size,
                                size_t n_elems)
{
    assert(map);
    assert(name);

    map->id = id;
    map->bpf_type = bpf_type;
    map->key_size = key_size;
    map->value_size = value_size;
    map->n_elems = n_elems;
    map->fd = -1;
    bf_strncpy(map->name, BPF_OBJ_NAME_LEN, name);
}

static uint32_t _bf_ct_opt_or_default(uint32_t opt, uint32_t def)
{
    return opt ? opt : def;
}

static int _bf_ct_maps_fill_defs(struct bf_ct_maps *maps,
                                 const struct bf_ct_maps_opts *opts)
{
    uint32_t max_tcp = BF_CT_MAP_TCP_MAX;
    uint32_t max_tcp6 = BF_CT_MAP_TCP6_MAX;
    uint32_t max_any = BF_CT_MAP_ANY_MAX;
    uint32_t max_any6 = BF_CT_MAP_ANY6_MAX;
    uint32_t max_src_rate = BF_CT_SRC_RATE_MAX;
    uint32_t max_src_count = BF_CT_SRC_COUNT_MAX;
    uint32_t max_spi_reverse = BF_CT_MAP_SPI_REVERSE_MAX;

    assert(maps);

    if (opts) {
        max_tcp = _bf_ct_opt_or_default(opts->max_tcp, max_tcp);
        max_tcp6 = _bf_ct_opt_or_default(opts->max_tcp6, max_tcp6);
        max_any = _bf_ct_opt_or_default(opts->max_any, max_any);
        max_any6 = _bf_ct_opt_or_default(opts->max_any6, max_any6);
        max_src_rate = _bf_ct_opt_or_default(opts->max_src_rate, max_src_rate);
        max_src_count =
            _bf_ct_opt_or_default(opts->max_src_count, max_src_count);
        max_spi_reverse =
            _bf_ct_opt_or_default(opts->max_spi_reverse, max_spi_reverse);
    }

    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_TCP], BF_CT_MAP_TCP,
                        BF_BPF_MAP_TYPE_LRU_HASH, "ct_map_tcp",
                        sizeof(struct ct_key_v4), sizeof(struct ct_entry),
                        max_tcp);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_TCP6], BF_CT_MAP_TCP6,
                        BF_BPF_MAP_TYPE_LRU_HASH, "ct_map_tcp6",
                        sizeof(struct ct_key_v6), sizeof(struct ct_entry),
                        max_tcp6);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_ANY], BF_CT_MAP_ANY,
                        BF_BPF_MAP_TYPE_LRU_HASH, "ct_map_any",
                        sizeof(struct ct_key_v4), sizeof(struct ct_entry),
                        max_any);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_ANY6], BF_CT_MAP_ANY6,
                        BF_BPF_MAP_TYPE_LRU_HASH, "ct_map_any6",
                        sizeof(struct ct_key_v6), sizeof(struct ct_entry),
                        max_any6);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_SRC_RATE], BF_CT_MAP_SRC_RATE,
                        BF_BPF_MAP_TYPE_LRU_PERCPU_HASH, "ct_src_rate",
                        sizeof(struct ct_ip_key), sizeof(struct ct_rate_entry),
                        max_src_rate);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_SRC_COUNT], BF_CT_MAP_SRC_COUNT,
                        BF_BPF_MAP_TYPE_LRU_HASH, "ct_src_count",
                        sizeof(struct ct_ip_key),
                        sizeof(struct ct_src_count_entry), max_src_count);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_SPI_REVERSE],
                        BF_CT_MAP_SPI_REVERSE, BF_BPF_MAP_TYPE_LRU_HASH,
                        "ct_spi_reverse", sizeof(struct ct_spi_reverse_key),
                        sizeof(__u32), max_spi_reverse);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_TIMEOUTS], BF_CT_MAP_TIMEOUTS,
                        BF_BPF_MAP_TYPE_ARRAY, "ct_timeouts", sizeof(__u32),
                        sizeof(struct ct_timeouts), 1);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_STATS], BF_CT_MAP_STATS,
                        BF_BPF_MAP_TYPE_PERCPU_ARRAY, "ct_stats", sizeof(__u32),
                        sizeof(struct ct_stats_counters), 1);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_TAIL_SCRATCH],
                        BF_CT_MAP_TAIL_SCRATCH,
                        BF_BPF_MAP_TYPE_PERCPU_ARRAY, "ct_tail_scratch_map",
                        sizeof(__u32), sizeof(struct ct_tail_scratch), 1);
    _bf_ct_map_init_def(&maps->maps[BF_CT_MAP_META], BF_CT_MAP_META,
                        BF_BPF_MAP_TYPE_ARRAY, "ct_meta", sizeof(__u32),
                        sizeof(struct ct_meta), 1);

    return 0;
}

static int _bf_ct_maps_open_dir(int pindir_fd, int *ct_dir_fd)
{
    int r;

    assert(ct_dir_fd);

    r = bf_opendir_at(pindir_fd, BF_CT_PIN_DIR, true);
    if (r < 0)
        return bf_err_r(r, "failed to open conntrack pin directory");

    *ct_dir_fd = r;

    return 0;
}

static int _bf_ct_maps_create_all(struct bf_ct_maps *maps, bool *any_created)
{
    int r;

    assert(maps);
    assert(any_created);

    *any_created = false;

    for (enum bf_ct_map_id id = 0; id < _BF_CT_MAP_MAX; ++id) {
        bool created = false;

        r = _bf_ct_map_create(&maps->maps[id], maps->ct_dir_fd, &created);
        if (r)
            return r;

        if (created)
            *any_created = true;
    }

    return 0;
}

int bf_ct_maps_init(struct bf_ct_maps **maps, int pindir_fd,
                    const struct bf_ct_maps_opts *opts)
{
    _free_bf_ct_maps_ struct bf_ct_maps *_maps = NULL;
    bool any_created = false;
    __u32 key = 0;
    int fd;
    int r;

    assert(maps);

    if (pindir_fd < 0)
        return bf_err_r(-EBADFD, "pindir_fd is invalid");

    _maps = calloc(1, sizeof(*_maps));
    if (!_maps)
        return -ENOMEM;

    _maps->ct_dir_fd = -1;

    r = _bf_ct_maps_open_dir(pindir_fd, &_maps->ct_dir_fd);
    if (r)
        return r;

    r = _bf_ct_maps_fill_defs(_maps, opts);
    if (r)
        return r;

    bf_ct_warn_map_memory(opts);

    r = _bf_ct_maps_create_all(_maps, &any_created);
    if (r)
        return r;

    r = bf_ct_maps_init_meta(_maps);
    if (r)
        return r;

    if (!any_created) {
        *maps = TAKE_PTR(_maps);
        return 0;
    }

    r = bf_ct_maps_init_timeouts(_maps);
    if (r)
        return r;

    fd = bf_ct_maps_get_fd(_maps, BF_CT_MAP_STATS);
    if (fd < 0)
        return fd;

    r = bf_bpf_map_update_elem(fd, &key, &(struct ct_stats_counters){}, BPF_ANY);
    if (r)
        return bf_err_r(r, "failed to initialize ct_stats map");

    *maps = TAKE_PTR(_maps);

    return 0;
}

int bf_ct_maps_open(struct bf_ct_maps **maps, int pindir_fd)
{
    return bf_ct_maps_init(maps, pindir_fd, NULL);
}

bool bf_ct_maps_exist(int pindir_fd)
{
    _cleanup_close_ int ct_dir_fd = -1;
    _cleanup_close_ int map_fd = -1;
    int r;

    if (pindir_fd < 0)
        return false;

    // Open the conntrack pin directory without creating it.
    r = bf_opendir_at(pindir_fd, BF_CT_PIN_DIR, false);
    if (r < 0)
        return false;
    ct_dir_fd = r;

    // ct_meta is created alongside every other map, so its presence is a
    // reliable proxy for "the conntrack maps are pinned".
    r = bf_bpf_obj_get("ct_meta", ct_dir_fd, &map_fd);

    return r == 0;
}

void bf_ct_maps_free(struct bf_ct_maps **maps)
{
    assert(maps);

    if (!*maps)
        return;

    for (enum bf_ct_map_id id = 0; id < _BF_CT_MAP_MAX; ++id)
        _bf_ct_map_close(&(*maps)->maps[id]);

    closep(&(*maps)->ct_dir_fd);
    BF_FREEP(maps);
}

int bf_ct_maps_pin(const struct bf_ct_maps *maps, int pindir_fd)
{
    _cleanup_close_ int ct_dir_fd = -1;
    int r;

    assert(maps);

    if (pindir_fd < 0)
        return bf_err_r(-EBADFD, "pindir_fd is invalid");

    r = _bf_ct_maps_open_dir(pindir_fd, &ct_dir_fd);
    if (r)
        return r;

    for (enum bf_ct_map_id id = 0; id < _BF_CT_MAP_MAX; ++id) {
        const struct bf_ct_map *map = &maps->maps[id];

        if (map->fd < 0)
            continue;

        r = bf_bpf_obj_pin(map->name, map->fd, ct_dir_fd);
        if (r)
            return bf_err_r(r, "failed to pin map '%s'", map->name);
    }

    return 0;
}

int bf_ct_maps_get_fd(const struct bf_ct_maps *maps, enum bf_ct_map_id id)
{
    assert(maps);

    if (id < 0 || id >= _BF_CT_MAP_MAX)
        return -EINVAL;

    return maps->maps[id].fd;
}

int bf_ct_maps_init_timeouts(struct bf_ct_maps *maps)
{
    struct ct_timeouts timeouts;
    __u32 key = 0;
    int fd;
    int r;

    assert(maps);

    fd = bf_ct_maps_get_fd(maps, BF_CT_MAP_TIMEOUTS);
    if (fd < 0)
        return fd;

    bf_ct_timeouts_defaults(&timeouts);
    bf_ct_timeouts_clamp(&timeouts);

    r = bf_bpf_map_update_elem(fd, &key, &timeouts, BPF_ANY);
    if (r)
        return bf_err_r(r, "failed to initialize ct_timeouts map");

    return 0;
}
