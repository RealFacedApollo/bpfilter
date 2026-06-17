#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Stress tail-call segment splitting: filler rules push the generated program
# past BF_CT_PROG_SPLIT_INSNS (8000). The accept rule lives in the final segment.
make_sandbox

PORT=18085
# Must exceed BF_CT_PROG_SPLIT_INSNS (8000); ~12 insns per filler rule on TC CT.
FILLER_RULES=288

RULES="rule ct.conntrack eq 0x6 ACCEPT"
for p in $(seq 1024 $((1024 + FILLER_RULES - 1))); do
    RULES="${RULES} rule tcp.dport eq ${p} DROP"
done
RULES="${RULES} rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_split_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP ${RULES}"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_split_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP ${RULES}"

${FROM_NS} nc -l -p ${PORT} >/dev/null &
NC_PID=$!
sleep 0.2

echo "handshake" | nc -w 2 ${NS_IP_ADDR} ${PORT}
wait ${NC_PID} || true

get_ct_stat() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_stats \
        | jq "[.[0].values[].value.${1}] | add"
}

new_tcp="$(get_ct_stat new_tcp)"
established="$(get_ct_stat established)"
test "${new_tcp}" -ge 1
test "${established}" -ge 1

${FROM_NS} ${BFCLI} ruleset flush
