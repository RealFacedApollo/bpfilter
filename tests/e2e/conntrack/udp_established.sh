#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PORT=18082

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule udp.dport eq ${PORT} ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule udp.sport eq ${PORT} ACCEPT"

${FROM_NS} nc -u -l -p ${PORT} >/dev/null &
NC_PID=$!
sleep 0.2

echo "probe" | nc -u -w 2 ${NS_IP_ADDR} ${PORT}
wait ${NC_PID} || true

get_ct_stat() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_stats | jq "[.[0].values[].value.${1}] | add"
}

new_udp="$(get_ct_stat new_udp)"
established="$(get_ct_stat established)"
test "${new_udp}" -ge 1
test "${established}" -ge 1

${FROM_NS} ${BFCLI} ruleset flush
