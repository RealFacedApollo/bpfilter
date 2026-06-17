#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

(! ${FROM_NS} ${BFCLI} chain set --from-str \
    "chain xdp_ct BF_HOOK_XDP{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq 443 ACCEPT")

${FROM_NS} ${BFCLI} ruleset flush
