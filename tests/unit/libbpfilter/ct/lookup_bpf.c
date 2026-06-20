// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/bpf.h>
#include <bpfilter/ct.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <bpf/libbpf.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"

#ifndef CT_HARNESS_BPF_PATH
#error "CT_HARNESS_BPF_PATH must be defined by CMake"
#endif

#define CT_TEST_OP_LOOKUP 0
#define CT_TEST_OP_LOOKUP_CREATE 1
#define CT_TEST_OP_LOOKUP_UPDATE_TCP 2

#define BF_CT_SCTP_CID_INIT 1
#define BF_CT_SCTP_CID_INIT_ACK 2
#define BF_CT_SCTP_CID_COOKIE_ECHO 10
#define BF_CT_SCTP_CID_COOKIE_ACK 11

struct ct_test_ctrl
{
    __u8 op;
    __u8 pad[7];
};

struct bft_ct_harness
{
    struct bpf_object *obj;
    int prog_fd;
    int ctrl_fd;
    int tcp_fd;
    int tcp6_fd;
    int any_fd;
    int any6_fd;
    int src_rate_fd;
    int src_count_fd;
    int spi_reverse_fd;
    int stats_fd;
};

struct bft_ct_pkt
{
    uint8_t *data;
    size_t len;
};

#define _free_bft_ct_pkt_ __attribute__((__cleanup__(_bft_ct_pkt_free)))

static void _bft_ct_pkt_free(struct bft_ct_pkt **pkt)
{
    if (!pkt || !*pkt)
        return;

    free((*pkt)->data);
    free(*pkt);
    *pkt = NULL;
}

static void _bft_require_linux(void)
{
    if (access("/sys/fs/bpf", F_OK) != 0)
        skip();
}

static __be16 _htons_u16(uint16_t v)
{
    return htobe16(v);
}

static __be32 _ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    __be32 val;
    uint8_t *p = (uint8_t *)&val;

    p[0] = a;
    p[1] = b;
    p[2] = c;
    p[3] = d;

    return val;
}

static int _bft_ct_map_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    int fd;

    if (!map)
        return -ENOENT;

    fd = bpf_map__fd(map);
    return fd >= 0 ? fd : -EBADF;
}

static int _bft_ct_harness_open(struct bft_ct_harness *h)
{
    struct bpf_program *prog;
    int r;

    assert(h);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    h->obj = bpf_object__open_file(CT_HARNESS_BPF_PATH, NULL);
    if (!h->obj)
        return -errno;

    r = bpf_object__load(h->obj);
    if (r)
        return r;

    prog = bpf_object__find_program_by_name(h->obj, "ct_harness");
    if (!prog)
        return -ENOENT;

    h->prog_fd = bpf_program__fd(prog);
    if (h->prog_fd < 0)
        return -EBADF;

    h->ctrl_fd = _bft_ct_map_fd(h->obj, "ct_test_ctrl");
    h->tcp_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_tcp");
    h->tcp6_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_tcp6");
    h->any_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_any");
    h->any6_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_any6");
    h->src_rate_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_src_rate");
    h->src_count_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_src_count");
    h->spi_reverse_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_spi_reverse");
    h->stats_fd = _bft_ct_map_fd(h->obj, "bf_ct_map_stats");

    if (h->ctrl_fd < 0 || h->tcp_fd < 0 || h->stats_fd < 0)
        return -ENOENT;

    return 0;
}

static void _bft_ct_harness_close(struct bft_ct_harness *h)
{
    if (!h)
        return;

    bpf_object__close(h->obj);
    memset(h, 0, sizeof(*h));
    h->prog_fd = -1;
}

static int _bft_ct_set_op(struct bft_ct_harness *h, __u8 op)
{
    struct ct_test_ctrl ctrl = { .op = op };
    __u32 key = 0;

    return bf_bpf_map_update_elem(h->ctrl_fd, &key, &ctrl, BPF_ANY);
}

static int _bft_ct_run(struct bft_ct_harness *h, const void *pkt, size_t len)
{
    return bf_bpf_prog_run(h->prog_fd, pkt, len, NULL, 0);
}

static int _bft_ct_stats_sum(struct bft_ct_harness *h, struct ct_stats_counters *out)
{
    int ncpu = libbpf_num_possible_cpus();
    __u32 key = 0;
    struct ct_stats_counters *percpu;
    int r;
    int i;

    if (ncpu <= 0)
        return -EINVAL;

    percpu = calloc((size_t)ncpu, sizeof(*percpu));
    if (!percpu)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(h->stats_fd, &key, percpu);
    if (r) {
        free(percpu);
        return r;
    }

    memset(out, 0, sizeof(*out));
    for (i = 0; i < ncpu; ++i) {
        out->new_tcp += percpu[i].new_tcp;
        out->new_udp += percpu[i].new_udp;
        out->new_icmp += percpu[i].new_icmp;
        out->new_other += percpu[i].new_other;
        out->established += percpu[i].established;
        out->related += percpu[i].related;
        out->invalid += percpu[i].invalid;
        out->dropped_rate_limit += percpu[i].dropped_rate_limit;
        out->dropped_src_count += percpu[i].dropped_src_count;
    }

    free(percpu);
    return 0;
}

static struct bft_ct_pkt *_bft_ct_build_tcp_v4(__be32 src, __be32 dst,
                                                __be16 sport, __be16 dport,
                                                __u8 tcp_flags)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    size_t ip_len = sizeof(*ip);
    size_t tcp_len = sizeof(*tcp);
    size_t total;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    total = sizeof(*eth) + ip_len + tcp_len;
    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(ip_len + tcp_len));
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src;
    ip->daddr = dst;

    tcp = (struct tcphdr *)(pkt->data + sizeof(*eth) + ip_len);
    tcp->source = sport;
    tcp->dest = dport;
    tcp->doff = 5;
    tcp->syn = !!(tcp_flags & 0x02);
    tcp->ack = !!(tcp_flags & 0x10);
    tcp->rst = !!(tcp_flags & 0x04);
    tcp->fin = !!(tcp_flags & 0x01);

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_udp_v4(__be32 src, __be32 dst,
                                               __be16 sport, __be16 dport)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    size_t ip_len = sizeof(*ip);
    size_t udp_len = sizeof(*udp);
    size_t total;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    total = sizeof(*eth) + ip_len + udp_len;
    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(ip_len + udp_len));
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = src;
    ip->daddr = dst;

    udp = (struct udphdr *)(pkt->data + sizeof(*eth) + ip_len);
    udp->source = sport;
    udp->dest = dport;
    udp->len = _htons_u16((uint16_t)udp_len);

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_icmp_echo_v4(__be32 src, __be32 dst,
                                                     __be16 id, __u8 type)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;
    size_t total;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    total = sizeof(*eth) + sizeof(*ip) + sizeof(*icmp);
    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(sizeof(*ip) + sizeof(*icmp)));
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = src;
    ip->daddr = dst;

    icmp = (struct icmphdr *)(pkt->data + sizeof(*eth) + sizeof(*ip));
    icmp->type = type;
    icmp->un.echo.id = id;

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_icmp_error_v4(__be32 outer_src,
                                                       __be32 outer_dst,
                                                       __be32 inner_src,
                                                       __be32 inner_dst,
                                                       __be16 inner_sport,
                                                       __be16 inner_dport)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;
    struct iphdr *inner_ip;
    struct tcphdr *inner_tcp;
    size_t icmp_payload;
    size_t total;

    icmp_payload = sizeof(*icmp) + sizeof(*inner_ip) + sizeof(*inner_tcp);
    total = sizeof(*eth) + sizeof(*ip) + icmp_payload;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(sizeof(*ip) + icmp_payload));
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = outer_src;
    ip->daddr = outer_dst;

    icmp = (struct icmphdr *)(pkt->data + sizeof(*eth) + sizeof(*ip));
    icmp->type = ICMP_DEST_UNREACH;

    inner_ip = (struct iphdr *)(icmp + 1);
    inner_ip->version = 4;
    inner_ip->ihl = 5;
    inner_ip->protocol = IPPROTO_TCP;
    inner_ip->saddr = inner_src;
    inner_ip->daddr = inner_dst;

    inner_tcp = (struct tcphdr *)(inner_ip + 1);
    inner_tcp->source = inner_sport;
    inner_tcp->dest = inner_dport;

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_icmpv6_echo_v6(const struct in6_addr *src,
                                                       const struct in6_addr *dst,
                                                       __be16 id, __u8 type)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp6;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6);
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IPV6);

    ip6 = (struct ipv6hdr *)(pkt->data + sizeof(*eth));
    ip6->version = 6;
    ip6->payload_len = _htons_u16(sizeof(*icmp6));
    ip6->nexthdr = IPPROTO_ICMPV6;
    ip6->hop_limit = 64;
    ip6->saddr = *src;
    ip6->daddr = *dst;

    icmp6 = (struct icmp6hdr *)(pkt->data + sizeof(*eth) + sizeof(*ip6));
    icmp6->icmp6_type = type;
    icmp6->icmp6_identifier = id;

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_icmpv6_error_v6(
    const struct in6_addr *outer_src, const struct in6_addr *outer_dst,
    const struct in6_addr *inner_src, const struct in6_addr *inner_dst,
    __be16 inner_sport, __be16 inner_dport)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp6;
    struct ipv6hdr *inner_ip6;
    struct tcphdr *inner_tcp;
    size_t icmp_payload;
    size_t total;

    icmp_payload = sizeof(*icmp6) + sizeof(*inner_ip6) + sizeof(*inner_tcp);
    total = sizeof(*eth) + sizeof(*ip6) + icmp_payload;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IPV6);

    ip6 = (struct ipv6hdr *)(pkt->data + sizeof(*eth));
    ip6->version = 6;
    ip6->payload_len = _htons_u16((uint16_t)icmp_payload);
    ip6->nexthdr = IPPROTO_ICMPV6;
    ip6->hop_limit = 64;
    ip6->saddr = *outer_src;
    ip6->daddr = *outer_dst;

    icmp6 = (struct icmp6hdr *)(pkt->data + sizeof(*eth) + sizeof(*ip6));
    icmp6->icmp6_type = ICMPV6_DEST_UNREACH;

    inner_ip6 = (struct ipv6hdr *)(icmp6 + 1);
    inner_ip6->version = 6;
    inner_ip6->payload_len = _htons_u16(sizeof(*inner_tcp));
    inner_ip6->nexthdr = IPPROTO_TCP;
    inner_ip6->hop_limit = 64;
    inner_ip6->saddr = *inner_src;
    inner_ip6->daddr = *inner_dst;

    inner_tcp = (struct tcphdr *)(inner_ip6 + 1);
    inner_tcp->source = inner_sport;
    inner_tcp->dest = inner_dport;

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_esp_v4(__be32 src, __be32 dst, __u32 spi)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    __u32 *spi_field;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip) + 8;
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(sizeof(*ip) + 8));
    ip->ttl = 64;
    ip->protocol = IPPROTO_ESP;
    ip->saddr = src;
    ip->daddr = dst;

    spi_field = (__u32 *)(pkt->data + sizeof(*eth) + sizeof(*ip));
    *spi_field = htobe32(spi);

    return TAKE_PTR(pkt);
}

static struct in6_addr _ipv6_words(uint32_t w0, uint32_t w1, uint32_t w2,
                                   uint32_t w3)
{
    struct in6_addr addr;
    uint32_t *words = (uint32_t *)&addr;

    words[0] = htobe32(w0);
    words[1] = htobe32(w1);
    words[2] = htobe32(w2);
    words[3] = htobe32(w3);

    return addr;
}

static struct bft_ct_pkt *_bft_ct_build_udp_v6(const struct in6_addr *src,
                                               const struct in6_addr *dst,
                                               __be16 sport, __be16 dport)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct udphdr *udp;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp);
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IPV6);

    ip6 = (struct ipv6hdr *)(pkt->data + sizeof(*eth));
    ip6->version = 6;
    ip6->payload_len = _htons_u16(sizeof(*udp));
    ip6->nexthdr = IPPROTO_UDP;
    ip6->hop_limit = 64;
    ip6->saddr = *src;
    ip6->daddr = *dst;

    udp = (struct udphdr *)(pkt->data + sizeof(*eth) + sizeof(*ip6));
    udp->source = sport;
    udp->dest = dport;
    udp->len = _htons_u16(sizeof(*udp));

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_tcp_v6(const struct in6_addr *src,
                                               const struct in6_addr *dst,
                                               __be16 sport, __be16 dport,
                                               __u8 tcp_flags)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct tcphdr *tcp;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip6) + sizeof(*tcp);
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IPV6);

    ip6 = (struct ipv6hdr *)(pkt->data + sizeof(*eth));
    ip6->version = 6;
    ip6->payload_len = _htons_u16(sizeof(*tcp));
    ip6->nexthdr = IPPROTO_TCP;
    ip6->hop_limit = 64;
    ip6->saddr = *src;
    ip6->daddr = *dst;

    tcp = (struct tcphdr *)(pkt->data + sizeof(*eth) + sizeof(*ip6));
    tcp->source = sport;
    tcp->dest = dport;
    tcp->doff = 5;
    tcp->syn = !!(tcp_flags & 0x02);
    tcp->ack = !!(tcp_flags & 0x10);
    tcp->rst = !!(tcp_flags & 0x04);
    tcp->fin = !!(tcp_flags & 0x01);

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_gre_v4(__be32 src, __be32 dst, __u32 key)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ethhdr *eth;
    struct iphdr *ip;
    __be16 *gre;
    __u32 *gre_key;
    size_t gre_len = 8;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip) + gre_len;
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data)
        return NULL;

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(sizeof(*ip) + gre_len));
    ip->ttl = 64;
    ip->protocol = IPPROTO_GRE;
    ip->saddr = src;
    ip->daddr = dst;

    gre = (__be16 *)(pkt->data + sizeof(*eth) + sizeof(*ip));
    gre[0] = _htons_u16(0x2000);
    gre[1] = _htons_u16(ETH_P_IP);
    gre_key = (__u32 *)(gre + 2);
    *gre_key = htobe32(key);

    return TAKE_PTR(pkt);
}

static struct bft_ct_pkt *_bft_ct_build_sctp_v4(__be32 src, __be32 dst,
                                               __be16 sport, __be16 dport,
                                               __u8 chunk_type)
{
    struct bft_ct_pkt *pkt;
    struct ethhdr *eth;
    struct iphdr *ip;
    __u8 *sctp;
    size_t sctp_len = 16;
    size_t total;

    total = sizeof(*eth) + sizeof(*ip) + sctp_len;
    pkt = calloc(1, sizeof(*pkt));
    if (!pkt)
        return NULL;

    pkt->data = calloc(1, total);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }

    pkt->len = total;

    eth = (struct ethhdr *)pkt->data;
    eth->h_proto = _htons_u16(ETH_P_IP);

    ip = (struct iphdr *)(pkt->data + sizeof(*eth));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = _htons_u16((uint16_t)(sizeof(*ip) + sctp_len));
    ip->ttl = 64;
    ip->protocol = IPPROTO_SCTP;
    ip->saddr = src;
    ip->daddr = dst;

    sctp = pkt->data + sizeof(*eth) + sizeof(*ip);
    *(__be16 *)&sctp[0] = sport;
    *(__be16 *)&sctp[2] = dport;
    sctp[12] = chunk_type;

    return pkt;
}

static void _bft_tcp_v6_handshake_steps(struct bft_ct_harness *h)
{
    struct in6_addr src = _ipv6_words(0x20010db8, 0, 0, 0x10);
    struct in6_addr dst = _ipv6_words(0x20010db8, 0, 0, 0x20);
    _free_bft_ct_pkt_ struct bft_ct_pkt *syn = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *synack = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *ack = NULL;

    syn = _bft_ct_build_tcp_v6(&src, &dst, _htons_u16(44000), _htons_u16(443),
                               0x02);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, syn->data, syn->len), CT_STATE_NEW);

    synack = _bft_ct_build_tcp_v6(&dst, &src, _htons_u16(443), _htons_u16(44000),
                                  0x12);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    /* The SYN-ACK is the reply direction, so the flow is now seen in both
     * directions and classifies as ESTABLISHED|REPLY (netfilter semantics),
     * even though the handshake is not yet complete. */
    assert_int_equal(_bft_ct_run(h, synack->data, synack->len),
                     CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    ack = _bft_ct_build_tcp_v6(&src, &dst, _htons_u16(44000), _htons_u16(443),
                               0x10);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    assert_int_equal(_bft_ct_run(h, ack->data, ack->len), CT_STATE_ESTABLISHED);
}

static void _bft_tcp_handshake_steps(struct bft_ct_harness *h)
{
    _free_bft_ct_pkt_ struct bft_ct_pkt *syn = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *synack = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *ack = NULL;

    syn = _bft_ct_build_tcp_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1),
                               _htons_u16(55000), _htons_u16(443), 0x02);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, syn->data, syn->len), CT_STATE_NEW);

    synack = _bft_ct_build_tcp_v4(_ipv4(10, 0, 0, 1), _ipv4(1, 2, 3, 4),
                                 _htons_u16(443), _htons_u16(55000), 0x12);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    /* The SYN-ACK is the reply direction, so the flow is now seen in both
     * directions and classifies as ESTABLISHED|REPLY (netfilter semantics),
     * even though the handshake is not yet complete. */
    assert_int_equal(_bft_ct_run(h, synack->data, synack->len),
                     CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    ack = _bft_ct_build_tcp_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1),
                               _htons_u16(55000), _htons_u16(443), 0x10);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    assert_int_equal(_bft_ct_run(h, ack->data, ack->len), CT_STATE_ESTABLISHED);
}

static struct ct_key_v4 _bft_tcp_key(void)
{
    struct ct_key_v4 key = {};
    bool orig_lo_is_src;

    bf_ct_key_normalize_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1), 55000, 443,
                           IPPROTO_TCP, &key, &orig_lo_is_src);
    return key;
}

static int _bft_ct_setup_harness(void **state)
{
    struct bft_ct_harness *h;
    int r;

    _bft_require_linux();

    h = calloc(1, sizeof(*h));
    if (!h)
        return -ENOMEM;

    h->prog_fd = -1;
    r = _bft_ct_harness_open(h);
    if (r) {
        _bft_ct_harness_close(h);
        free(h);
        skip();
    }

    *state = h;
    return 0;
}

static int _bft_ct_teardown_harness(void **state)
{
    struct bft_ct_harness *h = *state;

    _bft_ct_harness_close(h);
    free(h);
    *state = NULL;

    return 0;
}

static void lookup_tcp_syn_new(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *pkt = NULL;
    struct ct_key_v4 key = _bft_tcp_key();
    struct ct_entry entry = {};
    int r;

    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));

    pkt = _bft_ct_build_tcp_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1),
                               _htons_u16(55000), _htons_u16(443), 0x02);
    assert_non_null(pkt);

    r = _bft_ct_run(h, pkt->data, pkt->len);
    assert_int_equal(r, CT_STATE_NEW);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry);
    assert_ok(r);
    assert_int_equal(entry.internal_state, CT_TCP_SYN_SENT);
}

static void lookup_tcp_handshake(void **state)
{
    struct bft_ct_harness *h = *state;

    _bft_tcp_handshake_steps(h);
}

static void lookup_tcp_reply(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *data = NULL;
    struct ct_key_v4 key = _bft_tcp_key();
    struct ct_entry entry = {};
    int r;

    _bft_tcp_handshake_steps(h);

    data = _bft_ct_build_tcp_v4(_ipv4(10, 0, 0, 1), _ipv4(1, 2, 3, 4),
                               _htons_u16(443), _htons_u16(55000), 0x10);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, data->data, data->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_SEEN_REPLY);
}

static void lookup_tcp_unsolicited_ack(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *ack = NULL;
    struct ct_key_v4 key = _bft_tcp_key();
    struct ct_entry entry = {};
    int r;

    ack = _bft_ct_build_tcp_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1),
                               _htons_u16(55000), _htons_u16(443), 0x10);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, ack->data, ack->len);
    assert_int_equal(r, CT_STATE_INVALID);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry);
    assert_int_not_equal(r, 0);
}

static void lookup_tcp_rst(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *rst = NULL;
    struct ct_key_v4 key = _bft_tcp_key();
    struct ct_entry entry = {};
    int r;

    _bft_tcp_handshake_steps(h);

    rst = _bft_ct_build_tcp_v4(_ipv4(1, 2, 3, 4), _ipv4(10, 0, 0, 1),
                               _htons_u16(55000), _htons_u16(443), 0x04);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    (void)_bft_ct_run(h, rst->data, rst->len);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_DYING);
}

static void lookup_udp_bidirectional(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *req = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *reply = NULL;
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v4(_ipv4(192, 168, 1, 1), _ipv4(192, 168, 1, 2), 1234,
                           53, IPPROTO_UDP, &key, &orig_lo_is_src);

    req = _bft_ct_build_udp_v4(_ipv4(192, 168, 1, 1), _ipv4(192, 168, 1, 2),
                               _htons_u16(1234), _htons_u16(53));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, req->data, req->len), CT_STATE_NEW);

    reply = _bft_ct_build_udp_v4(_ipv4(192, 168, 1, 2), _ipv4(192, 168, 1, 1),
                                 _htons_u16(53), _htons_u16(1234));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, reply->data, reply->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, req->data, req->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED);

    r = bf_bpf_map_lookup_elem(h->any_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_SEEN_REPLY);
}

static void lookup_icmp_echo(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *req = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *reply = NULL;
    struct ct_key_v4 key = {};
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v4(_ipv4(10, 0, 0, 1), _ipv4(10, 0, 0, 2), 7, 0,
                           IPPROTO_ICMP, &key, &orig_lo_is_src);

    req = _bft_ct_build_icmp_echo_v4(_ipv4(10, 0, 0, 1), _ipv4(10, 0, 0, 2),
                                     _htons_u16(7), ICMP_ECHO);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, req->data, req->len), CT_STATE_NEW);

    reply = _bft_ct_build_icmp_echo_v4(_ipv4(10, 0, 0, 2), _ipv4(10, 0, 0, 1),
                                       _htons_u16(7), ICMP_ECHOREPLY);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, reply->data, reply->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);
}

static void lookup_icmp_related(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *err = NULL;
    struct ct_key_v4 key = _bft_tcp_key();
    struct ct_key_v4 outer_key = {};
    struct ct_entry entry_before = {};
    struct ct_entry entry_after = {};
    struct ct_entry outer_entry = {};
    bool orig_lo_is_src;
    __u64 before_ns;
    int r;

    _bft_tcp_handshake_steps(h);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry_before);
    assert_ok(r);
    before_ns = entry_before.last_seen_ns;

    err = _bft_ct_build_icmp_error_v4(
        _ipv4(10, 0, 0, 99), _ipv4(1, 2, 3, 4), _ipv4(1, 2, 3, 4),
        _ipv4(10, 0, 0, 1), _htons_u16(55000), _htons_u16(443));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, err->data, err->len);
    assert_int_equal(r, CT_STATE_RELATED);

    r = bf_bpf_map_lookup_elem(h->tcp_fd, &key, &entry_after);
    assert_ok(r);
    assert_true(entry_after.last_seen_ns >= before_ns);

    bf_ct_key_normalize_v4(_ipv4(10, 0, 0, 99), _ipv4(1, 2, 3, 4), 0, 0,
                           IPPROTO_ICMP, &outer_key, &orig_lo_is_src);
    r = bf_bpf_map_lookup_elem(h->any_fd, &outer_key, &outer_entry);
    assert_int_not_equal(r, 0);
}

static void lookup_icmpv6_echo(void **state)
{
    struct bft_ct_harness *h = *state;
    struct in6_addr src = _ipv6_words(0x20010db8, 0, 0, 0x100);
    struct in6_addr dst = _ipv6_words(0x20010db8, 0, 0, 0x200);
    _free_bft_ct_pkt_ struct bft_ct_pkt *req = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *reply = NULL;
    struct ct_key_v6 key = {};
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v6(&src, &dst, 7, 0, IPPROTO_ICMPV6, &key,
                           &orig_lo_is_src);

    req = _bft_ct_build_icmpv6_echo_v6(&src, &dst, _htons_u16(7),
                                       ICMPV6_ECHO_REQUEST);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, req->data, req->len), CT_STATE_NEW);

    reply = _bft_ct_build_icmpv6_echo_v6(&dst, &src, _htons_u16(7),
                                         ICMPV6_ECHO_REPLY);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, reply->data, reply->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);
}

static void lookup_icmpv6_related(void **state)
{
    struct bft_ct_harness *h = *state;
    struct in6_addr src = _ipv6_words(0x20010db8, 0, 0, 0x10);
    struct in6_addr dst = _ipv6_words(0x20010db8, 0, 0, 0x20);
    struct in6_addr err_src = _ipv6_words(0x20010db8, 0, 0, 0x99);
    _free_bft_ct_pkt_ struct bft_ct_pkt *err = NULL;
    struct ct_key_v6 tcp_key = {};
    struct ct_key_v6 outer_key = {};
    struct ct_entry entry_before = {};
    struct ct_entry entry_after = {};
    struct ct_entry outer_entry = {};
    bool orig_lo_is_src;
    __u64 before_ns;
    int r;

    _bft_tcp_v6_handshake_steps(h);

    bf_ct_key_normalize_v6(&src, &dst, 44000, 443, IPPROTO_TCP, &tcp_key,
                           &orig_lo_is_src);

    r = bf_bpf_map_lookup_elem(h->tcp6_fd, &tcp_key, &entry_before);
    assert_ok(r);
    before_ns = entry_before.last_seen_ns;

    err = _bft_ct_build_icmpv6_error_v6(&err_src, &src, &src, &dst,
                                          _htons_u16(44000), _htons_u16(443));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, err->data, err->len);
    assert_int_equal(r, CT_STATE_RELATED);

    r = bf_bpf_map_lookup_elem(h->tcp6_fd, &tcp_key, &entry_after);
    assert_ok(r);
    assert_true(entry_after.last_seen_ns >= before_ns);

    bf_ct_key_normalize_v6(&err_src, &src, 0, 0, IPPROTO_ICMPV6, &outer_key,
                           &orig_lo_is_src);
    r = bf_bpf_map_lookup_elem(h->any6_fd, &outer_key, &outer_entry);
    assert_int_not_equal(r, 0);
}

static void lookup_esp_reply_no_reverse(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *fwd = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *rev = NULL;
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    __u32 orig_spi = 0x33333333;
    __u32 reply_spi = 0x44444444;
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v4(_ipv4(10, 2, 0, 1), _ipv4(10, 2, 0, 2), orig_spi,
                           0, IPPROTO_ESP, &key, &orig_lo_is_src);

    fwd = _bft_ct_build_esp_v4(_ipv4(10, 2, 0, 1), _ipv4(10, 2, 0, 2),
                               orig_spi);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, fwd->data, fwd->len), CT_STATE_NEW);

    rev = _bft_ct_build_esp_v4(_ipv4(10, 2, 0, 2), _ipv4(10, 2, 0, 1),
                               reply_spi);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, rev->data, rev->len);
    assert_int_equal(r, CT_STATE_NEW);

    r = bf_bpf_map_lookup_elem(h->any_fd, &key, &entry);
    assert_ok(r);
    assert_int_equal(entry.reply_discriminator, 0);
}

static void lookup_esp_spi_reverse(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *fwd = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *rev = NULL;
    struct ct_spi_reverse_key rev_key = {};
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    __u32 orig_spi = 0x11111111;
    __u32 mapped_spi = 0;
    __u32 reply_spi = 0x22222222;
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v4(_ipv4(10, 1, 0, 1), _ipv4(10, 1, 0, 2), orig_spi,
                           0, IPPROTO_ESP, &key, &orig_lo_is_src);

    fwd = _bft_ct_build_esp_v4(_ipv4(10, 1, 0, 1), _ipv4(10, 1, 0, 2),
                               orig_spi);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, fwd->data, fwd->len), CT_STATE_NEW);

    rev_key.lo_ip = key.lo_ip;
    rev_key.hi_ip = key.hi_ip;
    rev_key.reply_spi = reply_spi;
    rev_key.proto = IPPROTO_ESP;
    assert_ok(bf_bpf_map_update_elem(h->spi_reverse_fd, &rev_key, &orig_spi,
                                     BPF_ANY));

    rev = _bft_ct_build_esp_v4(_ipv4(10, 1, 0, 2), _ipv4(10, 1, 0, 1),
                               reply_spi);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, rev->data, rev->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    r = bf_bpf_map_lookup_elem(h->any_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_SEEN_REPLY);
    assert_int_equal(entry.reply_discriminator, reply_spi);

    r = bf_bpf_map_lookup_elem(h->spi_reverse_fd, &rev_key, &mapped_spi);
    assert_ok(r);
    assert_int_equal(mapped_spi, orig_spi);
}

static void lookup_rate_limit(void **state)
{
    struct bft_ct_harness *h = *state;
    struct ct_stats_counters stats = {};
    int i;

    for (i = 0; i < CT_RATE_LIMIT_TCP + 1; ++i) {
        _free_bft_ct_pkt_ struct bft_ct_pkt *syn = NULL;

        syn = _bft_ct_build_tcp_v4(_ipv4(203, 0, 113, 9), _ipv4(10, 0, 0, 1),
                                   _htons_u16((uint16_t)(1000 + i)),
                                   _htons_u16(443), 0x02);
        assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
        (void)_bft_ct_run(h, syn->data, syn->len);
    }

    assert_ok(_bft_ct_stats_sum(h, &stats));
    assert_true(stats.dropped_rate_limit >= 1);
}

static void lookup_udp_v6_bidirectional(void **state)
{
    struct bft_ct_harness *h = *state;
    struct in6_addr src = _ipv6_words(0x20010db8, 0, 0, 1);
    struct in6_addr dst = _ipv6_words(0x20010db8, 0, 0, 2);
    _free_bft_ct_pkt_ struct bft_ct_pkt *req = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *reply = NULL;
    struct ct_key_v6 key = {};
    struct ct_entry entry = {};
    bool orig_lo_is_src;
    int r;

    bf_ct_key_normalize_v6(&src, &dst, 1234, 53, IPPROTO_UDP, &key,
                           &orig_lo_is_src);

    req = _bft_ct_build_udp_v6(&src, &dst, _htons_u16(1234), _htons_u16(53));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, req->data, req->len), CT_STATE_NEW);

    reply = _bft_ct_build_udp_v6(&dst, &src, _htons_u16(53), _htons_u16(1234));
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, reply->data, reply->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    r = bf_bpf_map_lookup_elem(h->any6_fd, &key, &entry);
    assert_ok(r);
    assert_true(entry.flags & CT_FLAG_SEEN_REPLY);
}

static void lookup_tcp_v6_handshake(void **state)
{
    struct bft_ct_harness *h = *state;

    _bft_tcp_v6_handshake_steps(h);
}

static void lookup_sctp_handshake(void **state)
{
    struct bft_ct_harness *h = *state;
    struct ct_key_v4 key = {};
    struct ct_entry entry = {};
    bool orig_lo_is_src;
    struct bft_ct_pkt *pkt = NULL;
    int r;

    bf_ct_key_normalize_v4(_ipv4(172, 16, 0, 1), _ipv4(172, 16, 0, 2), 5000,
                           5000, IPPROTO_SCTP, &key, &orig_lo_is_src);

    _bft_ct_pkt_free(&pkt);
    pkt = _bft_ct_build_sctp_v4(_ipv4(172, 16, 0, 1), _ipv4(172, 16, 0, 2),
                                _htons_u16(5000), _htons_u16(5000),
                                BF_CT_SCTP_CID_INIT);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, pkt->data, pkt->len), CT_STATE_NEW);

    _bft_ct_pkt_free(&pkt);
    pkt = _bft_ct_build_sctp_v4(_ipv4(172, 16, 0, 2), _ipv4(172, 16, 0, 1),
                                _htons_u16(5000), _htons_u16(5000),
                                BF_CT_SCTP_CID_INIT_ACK);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    /* INIT-ACK is the reply direction: flow now seen both ways. */
    assert_int_equal(_bft_ct_run(h, pkt->data, pkt->len),
                     CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    _bft_ct_pkt_free(&pkt);
    pkt = _bft_ct_build_sctp_v4(_ipv4(172, 16, 0, 1), _ipv4(172, 16, 0, 2),
                                _htons_u16(5000), _htons_u16(5000),
                                BF_CT_SCTP_CID_COOKIE_ECHO);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    /* Forward packet, but the reply (INIT-ACK) was already seen, so the flow is
     * established in both directions. */
    assert_int_equal(_bft_ct_run(h, pkt->data, pkt->len), CT_STATE_ESTABLISHED);

    _bft_ct_pkt_free(&pkt);
    pkt = _bft_ct_build_sctp_v4(_ipv4(172, 16, 0, 2), _ipv4(172, 16, 0, 1),
                                _htons_u16(5000), _htons_u16(5000),
                                BF_CT_SCTP_CID_COOKIE_ACK);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_UPDATE_TCP));
    assert_int_equal(_bft_ct_run(h, pkt->data, pkt->len),
                     CT_STATE_ESTABLISHED | CT_STATE_REPLY);

    r = bf_bpf_map_lookup_elem(h->any_fd, &key, &entry);
    assert_ok(r);
    assert_int_equal(entry.internal_state, CT_SCTP_ESTABLISHED);

    _bft_ct_pkt_free(&pkt);
}

static void lookup_gre_bidirectional(void **state)
{
    struct bft_ct_harness *h = *state;
    struct ct_key_v4 key = {};
    bool orig_lo_is_src;
    _free_bft_ct_pkt_ struct bft_ct_pkt *req = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *reply = NULL;
    int r;

    bf_ct_key_normalize_v4(_ipv4(10, 10, 0, 1), _ipv4(10, 10, 0, 2), 0x1234, 0,
                           IPPROTO_GRE, &key, &orig_lo_is_src);

    req = _bft_ct_build_gre_v4(_ipv4(10, 10, 0, 1), _ipv4(10, 10, 0, 2), 0x1234);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, req->data, req->len), CT_STATE_NEW);

    reply = _bft_ct_build_gre_v4(_ipv4(10, 10, 0, 2), _ipv4(10, 10, 0, 1), 0x1234);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP));
    r = _bft_ct_run(h, reply->data, reply->len);
    assert_int_equal(r, CT_STATE_ESTABLISHED | CT_STATE_REPLY);
}

static void lookup_gre_different_key(void **state)
{
    struct bft_ct_harness *h = *state;
    _free_bft_ct_pkt_ struct bft_ct_pkt *first = NULL;
    _free_bft_ct_pkt_ struct bft_ct_pkt *second = NULL;
    int r;

    first = _bft_ct_build_gre_v4(_ipv4(10, 10, 0, 1), _ipv4(10, 10, 0, 2),
                                 0x1234);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    assert_int_equal(_bft_ct_run(h, first->data, first->len), CT_STATE_NEW);

    second = _bft_ct_build_gre_v4(_ipv4(10, 10, 0, 1), _ipv4(10, 10, 0, 2),
                                  0x5678);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    r = _bft_ct_run(h, second->data, second->len);
    assert_int_equal(r, CT_STATE_NEW);
}

static void lookup_src_count_limit(void **state)
{
    struct bft_ct_harness *h = *state;
    struct ct_stats_counters stats = {};
    struct ct_ip_key ip_key = {};
    struct ct_src_count_entry count = {
        .count = CT_MAX_ENTRIES_PER_SRC_TCP,
    };
    _free_bft_ct_pkt_ struct bft_ct_pkt *syn = NULL;

    /* §13.2 layer 2: pre-seed count to isolate entry cap from rate limit. */
    bf_ct_ip_key_from_v4(_ipv4(198, 51, 100, 1), &ip_key);
    assert_ok(bf_bpf_map_update_elem(h->src_count_fd, &ip_key, &count, BPF_ANY));

    syn = _bft_ct_build_tcp_v4(_ipv4(198, 51, 100, 1), _ipv4(10, 0, 0, 1),
                               _htons_u16(20000), _htons_u16(443), 0x02);
    assert_ok(_bft_ct_set_op(h, CT_TEST_OP_LOOKUP_CREATE));
    (void)_bft_ct_run(h, syn->data, syn->len);

    assert_ok(_bft_ct_stats_sum(h, &stats));
    assert_true(stats.dropped_src_count >= 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(lookup_tcp_syn_new,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_tcp_handshake,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_tcp_reply,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_tcp_unsolicited_ack,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_tcp_rst,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_udp_bidirectional,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_icmp_echo,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_icmp_related,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_icmpv6_echo,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_icmpv6_related,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_udp_v6_bidirectional,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_tcp_v6_handshake,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_sctp_handshake,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_gre_bidirectional,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_gre_different_key,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_esp_spi_reverse,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_esp_reply_no_reverse,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_rate_limit,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
        cmocka_unit_test_setup_teardown(lookup_src_count_limit,
                                        _bft_ct_setup_harness,
                                        _bft_ct_teardown_harness),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
