#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PORT=18081
OUT="${WORKDIR}/server.out"

# ESTABLISHED fast path, then dport ACCEPT (creates on SYN).
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} nc -l -p ${PORT} >"${OUT}" &
NC_PID=$!
sleep 0.2

(echo phase1; sleep 2; echo phase2) | nc -w 10 ${NS_IP_ADDR} ${PORT} &
CLIENT_PID=$!

sleep 0.5

get_ct_stat() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_stats | jq "[.[0].values[].value.${1}] | add"
}

count_tcp_entries() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_map_tcp | jq 'length'
}

established_before="$(get_ct_stat established)"
entries_before="$(count_tcp_entries)"
test "${established_before}" -ge 1
test "${entries_before}" -ge 1

${FROM_NS} ${BFCLI} chain update --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule ip4.proto tcp log counter NEXT \
     rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} ${BFCLI} chain update --from-str \
    "chain ct_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule ip4.proto tcp log counter NEXT \
     rule tcp.dport eq ${PORT} ACCEPT"

wait ${CLIENT_PID}
wait ${NC_PID} || true

grep -q phase1 "${OUT}"
grep -q phase2 "${OUT}"

established_after="$(get_ct_stat established)"
entries_after="$(count_tcp_entries)"
test "${established_after}" -ge "${established_before}"
test "${entries_after}" -ge 1

${FROM_NS} ${BFCLI} ruleset flush
