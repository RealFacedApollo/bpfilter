/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/in.h>

#include <assert.h>

#include <bpfilter/ct.h>

__u64 bf_ct_get_timeout_ns(const struct ct_entry *e,
                           const struct ct_timeouts *t)
{
    assert(e);
    assert(t);

    if (!(e->flags & CT_FLAG_SEEN_REPLY)) {
        switch (e->proto) {
        case IPPROTO_TCP:
            return t->tcp_syn_ns;
        case IPPROTO_SCTP:
            return t->sctp_init_ns;
        default:
            return t->udp_new_ns;
        }
    }

    switch (e->proto) {
    case IPPROTO_TCP:
        switch ((enum ct_tcp_state)e->internal_state) {
        case CT_TCP_ESTABLISHED:
            return t->tcp_established_ns;
        case CT_TCP_FIN_WAIT:
            return t->tcp_fin_wait_ns;
        case CT_TCP_TIME_WAIT:
            return t->tcp_time_wait_ns;
        case CT_TCP_CLOSE:
            return t->tcp_close_ns;
        default:
            return t->tcp_syn_ns;
        }
    case IPPROTO_UDP:
        return t->udp_established_ns;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return t->icmp_ns;
    case IPPROTO_SCTP:
        switch ((enum ct_sctp_state)e->internal_state) {
        case CT_SCTP_ESTABLISHED:
            return t->sctp_established_ns;
        case CT_SCTP_SHUTDOWN:
            return t->sctp_shutdown_ns;
        default:
            return t->sctp_init_ns;
        }
    case IPPROTO_ESP:
    case IPPROTO_AH:
        return t->ipsec_ns;
    case IPPROTO_GRE:
        return t->gre_ns;
    default:
        return t->generic_ns;
    }
}
