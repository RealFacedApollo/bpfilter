#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PORT=18084
TIMEOUTS_PIN="${WORKDIR}/bpf/bpfilter/ct/ct_timeouts"
ONE_SEC=1000000000

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_ing BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ct_egr BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} DROP \
     rule ct.conntrack eq 0x6 ACCEPT \
     rule tcp.dport eq ${PORT} ACCEPT"

${FROM_NS} nc -l -p ${PORT} >/dev/null &
NC_PID=$!
sleep 0.2

echo "handshake" | nc -w 2 ${NS_IP_ADDR} ${PORT}
wait ${NC_PID} || true

count_tcp_entries() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/ct/ct_map_tcp | jq 'length'
}

entries_before="$(count_tcp_entries)"
test "${entries_before}" -ge 1

python3 - "${TIMEOUTS_PIN}" "${ONE_SEC}" <<'PY'
import struct
import subprocess
import sys

path, one_sec = sys.argv[1], int(sys.argv[2])
value = struct.pack("<14Q", *([one_sec] * 14))
hex_bytes = " ".join(f"{b:02x}" for b in value)
subprocess.run(
    [
        "bpftool",
        "map",
        "update",
        "pinned",
        path,
        "key",
        "0",
        "0",
        "0",
        "0",
        "value",
        hex_bytes,
    ],
    check=True,
)
PY

sleep 2

${FROM_NS} ${BFCLI} ct gc sweep --once
${FROM_NS} ${BFCLI} ct gc sweep --once

entries_after="$(count_tcp_entries)"
test "${entries_after}" -eq 0

${FROM_NS} ${BFCLI} ruleset flush
