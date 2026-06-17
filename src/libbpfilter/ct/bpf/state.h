/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/ct.h>

#include <linux/tcp.h>
#include <linux/types.h>

static __always_inline __u8
bf_ct_entry_to_rule_state(const struct ct_entry *e, bool is_reply)
{
    if (e->flags & CT_FLAG_INVALID)
        return CT_STATE_INVALID;

    if (e->flags & CT_FLAG_RELATED)
        return CT_STATE_RELATED;

    if (e->proto == IPPROTO_TCP) {
        if (e->internal_state < CT_TCP_ESTABLISHED)
            return CT_STATE_NEW;
        if (is_reply)
            return CT_STATE_ESTABLISHED | CT_STATE_REPLY;
        return CT_STATE_ESTABLISHED;
    }

    if (e->proto == IPPROTO_SCTP) {
        if (e->internal_state < CT_SCTP_ESTABLISHED)
            return CT_STATE_NEW;
        if (is_reply)
            return CT_STATE_ESTABLISHED | CT_STATE_REPLY;
        return CT_STATE_ESTABLISHED;
    }

    if (is_reply)
        return CT_STATE_ESTABLISHED | CT_STATE_REPLY;

    if (e->flags & CT_FLAG_SEEN_REPLY)
        return CT_STATE_ESTABLISHED;

    return CT_STATE_NEW;
}

static __always_inline void
bf_ct_bpf_tcp_fsm(struct ct_entry *e, const struct tcphdr *tcp, __u8 is_reply)
{
    if (tcp->rst) {
        e->internal_state = CT_TCP_CLOSE;
        e->flags |= CT_FLAG_DYING | CT_FLAG_INVALID;
        return;
    }

    if (e->internal_state >= CT_TCP_ESTABLISHED && tcp->syn && is_reply)
        e->flags |= CT_FLAG_INVALID;

    switch ((enum ct_tcp_state)e->internal_state) {
    case CT_TCP_SYN_SENT:
        if (tcp->syn && tcp->ack)
            e->internal_state = CT_TCP_SYN_RECV;
        break;
    case CT_TCP_SYN_RECV:
        if (tcp->ack && !tcp->syn) {
            e->internal_state = CT_TCP_ESTABLISHED;
            e->flags |= CT_FLAG_ASSURED | CT_FLAG_SEEN_REPLY;
        }
        break;
    case CT_TCP_ESTABLISHED:
        if (tcp->fin)
            e->internal_state = CT_TCP_FIN_WAIT;
        break;
    case CT_TCP_FIN_WAIT:
        if (tcp->fin && tcp->ack)
            e->internal_state = CT_TCP_TIME_WAIT;
        break;
    default:
        break;
    }
}

#define BF_CT_SCTP_CID_INIT 1
#define BF_CT_SCTP_CID_INIT_ACK 2
#define BF_CT_SCTP_CID_COOKIE_ECHO 10
#define BF_CT_SCTP_CID_COOKIE_ACK 11
#define BF_CT_SCTP_CID_SHUTDOWN 7
#define BF_CT_SCTP_CID_SHUTDOWN_ACK 8

static __always_inline void bf_ct_bpf_sctp_fsm(struct ct_entry *e,
                                               __u8 chunk_type,
                                               __u8 is_reply)
{
    switch ((enum ct_sctp_state)e->internal_state) {
    case CT_SCTP_NONE:
        if (chunk_type == BF_CT_SCTP_CID_INIT)
            e->internal_state = CT_SCTP_INIT;
        break;
    case CT_SCTP_INIT:
        if (chunk_type == BF_CT_SCTP_CID_INIT_ACK && is_reply)
            e->internal_state = CT_SCTP_INIT_ACK;
        break;
    case CT_SCTP_INIT_ACK:
        if (chunk_type == BF_CT_SCTP_CID_COOKIE_ECHO)
            ;
        else if (chunk_type == BF_CT_SCTP_CID_COOKIE_ACK) {
            e->internal_state = CT_SCTP_ESTABLISHED;
            e->flags |= CT_FLAG_ASSURED | CT_FLAG_SEEN_REPLY;
        }
        break;
    case CT_SCTP_ESTABLISHED:
        if (chunk_type == BF_CT_SCTP_CID_SHUTDOWN)
            e->internal_state = CT_SCTP_SHUTDOWN;
        break;
    case CT_SCTP_SHUTDOWN:
        if (chunk_type == BF_CT_SCTP_CID_SHUTDOWN_ACK)
            e->internal_state = CT_SCTP_CLOSE;
        break;
    default:
        break;
    }
}
