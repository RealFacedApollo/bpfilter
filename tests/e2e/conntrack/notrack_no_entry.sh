#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PORT=18083

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule udp.dport eq ${PORT} notrack ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule udp.sport eq ${PORT} notrack ACCEPT"

${FROM_NS} nc -u -l -p ${PORT} >/dev/null &
NC_PID=$!
sleep 0.2

echo "probe" | nc -u -w 2 ${NS_IP_ADDR} ${PORT}
wait ${NC_PID} || true

get_ct_stat() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_stats | jq "[.[0].values[].value.${1}] | add"
}

count_any_entries() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_map_any | jq 'length'
}

new_udp="$(get_ct_stat new_udp)"
entries="$(count_any_entries)"
test "${new_udp}" -eq 0
test "${entries}" -eq 0

${FROM_NS} ${BFCLI} ruleset flush
