#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PORT=18086
CT_DIR="${WORKDIR}/bpf/bpfilter/ct"

# A purely stateless ruleset (ACCEPT rules, no ct.conntrack matcher) must not
# allocate the host-global conntrack maps.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain st_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule tcp.dport eq ${PORT} ACCEPT"

test ! -e "${CT_DIR}/ct_map_tcp"
test ! -e "${CT_DIR}/ct_meta"

${FROM_NS} ${BFCLI} ruleset flush

# Loading a chain that consults connection state arms conntrack lazily; the
# maps appear once the consumer is loaded.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq ${PORT} ACCEPT"

test -e "${CT_DIR}/ct_map_tcp"
test -e "${CT_DIR}/ct_meta"

${FROM_NS} ${BFCLI} ruleset flush
