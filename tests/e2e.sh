#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
#
# tcxflow end-to-end test.
#
#   lan (10.10.1.2) --- [dp-lan   dp   dp-up] --- wan (192.0.2.2, 192.0.2.3)
#                              [dp   trk] === wtrk   VLAN 300: 10.30.0.1 - 10.30.0.2
#                                                              QinQ 400/500: 10.45.0.1 - 10.45.0.2
#                              [dp  tcol] --- wan    quiet: the collector restart test
#
# "dp" plays the router's dataplane namespace, "mgmt" its management side. tcxflow runs in mgmt
# with "netns dp", meters dp-up, the trunk trk and its VLAN interface trk.300, and exports IPFIX
# to two nfcapd collectors in mgmt. The test sends traffic with known packet and byte counts, then
# checks "tcxflow stats", "tcxflow interfaces" and the records nfdump decoded, and that a
# restarted collector decodes the first message it gets. Finally it replaces a metered interface
# by one with the same name and index, and deletes "dp", under a running tcxflow: both times it
# must exit with status 1.
#
# The namespaces get unique names (tcxf<pid>-lan, ...), and tcxflow and its collectors live in
# their own: the test can run on a live host without touching its namespaces or services.
#
# Needs root, iproute2, nfdump (nfcapd), iperf3.   Usage: sudo tests/e2e.sh

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TCXFLOW=${TCXFLOW:-$HERE/../tcxflow}
WORK=$(mktemp -d /tmp/tcxflow-e2e.XXXXXX)
NS=tcxf$$
LAN=$NS-lan
DP=$NS-dp
WAN=$NS-wan
MGMT=$NS-mgmt
TCX=(ip netns exec "$MGMT" "$TCXFLOW") # tcxflow on the management side
PORT1=4739
PORT2=4740
PORT3=4741
V6=0
[[ -d /proc/sys/net/ipv6 ]] && V6=1
FAIL=0
PIDS=()

[[ $EUID == 0 ]] || { echo "run as root"; exit 1; }
for tool in ip nfcapd nfdump iperf3; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool"; exit 1; }
done

# Every background process is in PIDS: the final wait must not hang on one that still runs.
# shellcheck disable=SC2317,SC2329 # invoked by the trap
cleanup() {
    kill "${PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    for ns in "$LAN" "$DP" "$WAN" "$MGMT"; do ip netns del "$ns" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

# Background processes: ip netns exec itself, so that $! is the process and not a subshell.
nsx() { ip netns exec "$@"; }
# TCP segments sent by a namespace, including retransmissions
# shellcheck disable=SC2016 # awk fields, not shell variables
tcp_sent() { nsx "$1" awk '/^Tcp:/ && $2 ~ /^[0-9]/ {print $12 + $13}' /proc/net/snmp; }
ok() { printf 'ok    %s\n' "$1"; }
# Wait until the daemon logged that it is attached (slow under valgrind or on a busy CI runner).
wait_started() { # pid, log file
    for _ in {1..150}; do
        grep -qs ' started: ' "$2" && return 0 # the shell may not have created the log yet
        kill -0 "$1" 2>/dev/null || break
        sleep 0.1
    done
    cat "$2"
    echo "tcxflow did not start"
    exit 1
}
fail() { printf 'FAIL  %s\n' "$1"; FAIL=1; }

# --- topology ----------------------------------------------------------------
for ns in "$LAN" "$DP" "$WAN" "$MGMT"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
ip link add lan0 netns "$LAN" type veth peer name dp-lan netns "$DP"
ip link add wan0 netns "$WAN" type veth peer name dp-up netns "$DP"
nsx "$LAN" ip addr add 10.10.1.2/24 dev lan0
nsx "$DP" ip addr add 10.10.1.1/24 dev dp-lan
nsx "$DP" ip addr add 192.0.2.1/24 dev dp-up
nsx "$WAN" ip addr add 192.0.2.2/24 dev wan0
nsx "$WAN" ip addr add 192.0.2.3/24 dev wan0
if ((V6)); then
    nsx "$LAN" ip addr add fd00:1::2/64 dev lan0 nodad
    nsx "$DP" ip addr add fd00:1::1/64 dev dp-lan nodad
    nsx "$DP" ip addr add 2001:db8::1/64 dev dp-up nodad
    nsx "$WAN" ip addr add 2001:db8::2/64 dev wan0 nodad
    nsx "$DP" sysctl -qw net.ipv6.conf.all.forwarding=1
fi
nsx "$LAN" ip link set lan0 up
nsx "$WAN" ip link set wan0 up
nsx "$DP" ip link set dp-lan up
nsx "$DP" ip link set dp-up up
nsx "$DP" sysctl -qw net.ipv4.ip_forward=1
nsx "$LAN" ip route add default via 10.10.1.1
nsx "$WAN" ip route add 10.10.1.0/24 via 192.0.2.1
if ((V6)); then
    nsx "$LAN" ip -6 route add default via fd00:1::1
    nsx "$WAN" ip -6 route add fd00:1::/64 via 2001:db8::1
fi
UP=$(nsx "$DP" cat /sys/class/net/dp-up/ifindex)
# A VLAN trunk: VLAN 300, and QinQ with service VLAN 400 (802.1ad) and customer VLAN 500.
ip link add trk netns "$DP" type veth peer name wtrk netns "$WAN"
for side in "$DP trk 1" "$WAN wtrk 2"; do
    read -r ns dev host <<<"$side"
    nsx "$ns" ip link set "$dev" up
    nsx "$ns" ip link add link "$dev" name "$dev.300" type vlan id 300
    nsx "$ns" ip link add link "$dev" name "$dev.400" type vlan proto 802.1ad id 400
    nsx "$ns" ip link add link "$dev.400" name "$dev.400.500" type vlan id 500
    nsx "$ns" ip addr add "10.30.0.$host/24" dev "$dev.300"
    nsx "$ns" ip addr add "10.45.0.$host/24" dev "$dev.400.500"
    for vdev in "$dev.300" "$dev.400" "$dev.400.500"; do nsx "$ns" ip link set "$vdev" up; done
done
TRUNK=$(nsx "$DP" cat /sys/class/net/trk/ifindex)
SUB300=$(nsx "$DP" cat /sys/class/net/trk.300/ifindex)

# --- collectors and exporter ---------------------------------------------------
cat >"$WORK/tcxflow.conf" <<EOF
# written by tests/e2e.sh
netns            $DP
interface        dp-up
interface        trk
interface        trk.300
collector        127.0.0.1:$PORT1
collector        127.0.0.1:$PORT2
inactive-timeout 2
active-timeout   2
export-interval  0
socket           $WORK/tcxflow.sock
EOF
mkdir "$WORK/c1" "$WORK/c2"
ip netns exec "$MGMT" nfcapd -b 127.0.0.1 -p "$PORT1" -w "$WORK/c1" >/dev/null 2>&1 &
PIDS+=($!)
ip netns exec "$MGMT" nfcapd -b 127.0.0.1 -p "$PORT2" -w "$WORK/c2" >/dev/null 2>&1 &
PIDS+=($!)
sleep 1
"${TCX[@]}" --config "$WORK/tcxflow.conf" >"$WORK/tcxflow.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
wait_started $DAEMON "$WORK/tcxflow.log"

# --- traffic with known counts ---------------------------------------------------
LAN0=$(tcp_sent "$LAN")
WAN0=$(tcp_sent "$WAN")
# 35 pings over 7 seconds: with active-timeout 2 the flow is exported in several records
ip netns exec "$LAN" ping -c 35 -i 0.2 -q 192.0.2.3 >/dev/null &
LONGPING=$!
PIDS+=("$LONGPING")
nsx "$LAN" ping -c 10 -i 0.2 -q 192.0.2.2 >/dev/null              # 10 x 84 bytes
nsx "$DP" ping -c 3 -i 0.2 -s 100 -q 192.0.2.2 >/dev/null         # 3 x 128 bytes, from the router
((V6)) && nsx "$LAN" ping -6 -c 5 -i 0.2 -q 2001:db8::2 >/dev/null # 5 x 104 bytes
# 1000 UDP datagrams with 1000 bytes payload, all from one socket (one flow). They go to a
# static neighbour that does not exist: no ICMP errors come back to disturb the sender.
nsx "$DP" ip neigh add 192.0.2.99 lladdr 02:00:00:00:00:99 dev dp-up nud permanent
nsx "$LAN" bash -c 'exec 3>/dev/udp/192.0.2.99/5000; for i in {1..1000}; do printf "%1000s" "" >&3; done'
nsx "$DP" ping -c 4 -i 0.2 -q 10.30.0.2 >/dev/null # VLAN 300
nsx "$DP" ping -c 3 -i 0.2 -q 10.45.0.2 >/dev/null # QinQ 400/500
ip netns exec "$WAN" iperf3 -s -1 >/dev/null 2>&1 & # not daemonized: a failed client must not leave it behind
PIDS+=($!)
sleep 0.5
nsx "$LAN" iperf3 -c 192.0.2.2 -n 50M >/dev/null # GSO/TSO traffic
LAN1=$(tcp_sent "$LAN")
WAN1=$(tcp_sent "$WAN")
wait $LONGPING
sleep 1.5

# --- query the running exporter ----------------------------------------------------
STATS=$("${TCX[@]}" --config "$WORK/tcxflow.conf" stats)
IFACES=$("${TCX[@]}" --config "$WORK/tcxflow.conf" interfaces)
PKTS=$(awk '$1 == "packets" {print $2}' <<<"$STATS")
if [[ $PKTS -gt 30000 ]] && grep -q '^interfaces *3 attached, 0 gone' <<<"$STATS"; then
    ok "tcxflow stats: $PKTS packets accounted"
else
    fail "tcxflow stats"
    echo "$STATS"
fi
# A second instance with the same control socket must refuse to start, and leave the first alone.
if ! "${TCX[@]}" --config "$WORK/tcxflow.conf" >"$WORK/second.log" 2>&1 && grep -q 'already running' "$WORK/second.log" &&
    kill -0 $DAEMON 2>/dev/null && "${TCX[@]}" --config "$WORK/tcxflow.conf" stats >/dev/null; then
    ok "second instance refused, the first still answers"
else
    fail "second instance"
    cat "$WORK/second.log"
fi
read -r _ IFINDEX _ _ STATUS INPKTS _ OUTPKTS _ < <(grep '^dp-up ' <<<"$IFACES")
if [[ $IFINDEX == "$UP" && $STATUS == attached && $INPKTS -gt 0 && $OUTPKTS -gt 30000 ]]; then
    ok "tcxflow interfaces: dp-up ifindex $IFINDEX, $INPKTS in / $OUTPKTS out packets"
else
    fail "tcxflow interfaces"
    echo "$IFACES"
fi

sleep 3 # inactive timeout (2 s) + one interval: everything exported
kill -TERM $DAEMON
RC=0
wait $DAEMON || RC=$?
if [[ $RC == 0 ]]; then
    ok "stopped with status 0: everything exported"
else
    fail "stopped with status $RC"
    cat "$WORK/tcxflow.log"
fi
# The final export may still wait in a collector's socket buffer: a collector stopped before it
# read it would miss records the other one has.
for _ in {1..50}; do
    queued=$(ip netns exec "$MGMT" ss -Hunl "( sport = :$PORT1 or sport = :$PORT2 )" | awk '{q += $2} END {print q + 0}')
    [[ $queued == 0 ]] && break
    sleep 0.1
done
kill "${PIDS[@]}" 2>/dev/null || true
wait 2>/dev/null || true
PIDS=()

# --- check the IPFIX records ---------------------------------------------------------
NFDUMP=(nfdump -R "$WORK/c1" -N -q)
total() { "${NFDUMP[@]}" -o 'fmt:%pkt %byt' "$1" | awk '{p += $1; b += $2} END {print p + 0, b + 0}'; }
check() { # description, nfdump filter, expected packets, expected bytes (- = any)
    local pkts bytes
    read -r pkts bytes < <(total "$2")
    if [[ $pkts == "$3" && ($4 == - || $bytes == "$4") ]]; then
        printf 'ok    %-36s %6s packets %9s bytes\n' "$1" "$pkts" "$bytes"
    else
        fail "$1: got $pkts/$bytes, expected $3/$4"
    fi
}

check "ICMP echo, forwarded out" "proto icmp and src ip 10.10.1.2 and dst ip 192.0.2.2 and out if $UP" 10 840
check "ICMP echo reply in" "proto icmp and icmp-type 0 and src ip 192.0.2.2 and dst ip 10.10.1.2 and in if $UP" 10 840
check "ICMP sent by the router" "proto icmp and src ip 192.0.2.1 and in if 0" 3 384
check "ICMP 35 x 84 bytes, long flow" "proto icmp and dst ip 192.0.2.3 and out if $UP" 35 2940
NREC=$("${NFDUMP[@]}" -o 'fmt:%pkt' "proto icmp and dst ip 192.0.2.3 and out if $UP" | wc -l)
if [[ $NREC -ge 3 ]]; then
    ok "active timeout: the 7 s ping flow was exported in $NREC records"
else
    fail "active timeout: the 7 s ping flow was exported in $NREC records, expected at least 3"
fi
check "UDP 1000 x 1000 bytes" "proto udp and dst port 5000 and out if $UP" 1000 1028000
check "TCP out = segments sent by lan" "proto tcp and src ip 10.10.1.2 and out if $UP" $((LAN1 - LAN0)) -
check "TCP in = segments sent by wan" "proto tcp and dst ip 10.10.1.2 and in if $UP" $((WAN1 - WAN0)) -
if ((V6)); then
    check "IPv6 ping, forwarded out" "proto icmp6 and src ip fd00:1::2 and out if $UP" 5 520
    check "IPv6 ping reply in" "proto icmp6 and dst ip fd00:1::2 and in if $UP" 5 520
fi
check "VLAN 300 out, trunk (tag)" "proto icmp and dst ip 10.30.0.2 and out if $TRUNK and dst vlan 300" 4 336
check "VLAN 300 in, trunk (tag)" "proto icmp and src ip 10.30.0.2 and in if $TRUNK and src vlan 300" 4 336
check "VLAN 300 out, trk.300 (config)" "proto icmp and dst ip 10.30.0.2 and out if $SUB300 and dst vlan 300" 4 336
check "QinQ out, trunk: service VLAN 400" "proto icmp and dst ip 10.45.0.2 and out if $TRUNK and dst vlan 400" 3 252
# nfdump 1.7 has no format tag for the customer VLAN (IPFIX 245/255); its JSON output shows it.
# Older versions (1.7.3 in Ubuntu 24.04) do not decode that element: then the service VLAN only.
JSON=$("${NFDUMP[@]}" -o json "proto icmp and src ip 10.45.0.2 and in if $TRUNK")
VL=$(awk -F' : ' '/"src_vlan"/ {v = $2 + 0} /"cust_vlanID"/ {print v "/" $2 + 0}' <<<"$JSON" | sort -u)
if [[ $VL == "400/500" ]]; then
    ok "QinQ in, trunk: VLAN 400, customer VLAN 500"
elif ! grep -q '"cust_vlanID"' <<<"$JSON" && grep -q '"src_vlan" : 400,' <<<"$JSON"; then
    ok "QinQ in, trunk: VLAN 400"
    printf 'SKIP  QinQ in, trunk: customer VLAN 500 (this nfdump does not decode IPFIX 245)\n'
else
    fail "QinQ in, trunk: VLAN/customer VLAN \"$VL\", expected 400/500"
    echo "$JSON"
fi
# Every record field by field, not just their number.
FMT='fmt:%ts %te %pr %sa %da %sp %dp %in %out %svln %dvln %flg %pkt %byt'
for c in c1 c2; do nfdump -R "$WORK/$c" -N -q -o "$FMT" | LC_ALL=C sort >"$WORK/$c.records"; done
R1=$(wc -l <"$WORK/c1.records")
if [[ $R1 -gt 0 ]] && cmp -s "$WORK/c1.records" "$WORK/c2.records"; then
    ok "both collectors received the same $R1 records"
else
    fail "collectors differ: $R1 vs $(wc -l <"$WORK/c2.records") records"
    diff "$WORK/c1.records" "$WORK/c2.records" | head -10
fi

# Wait for a tcxflow that must exit with status 1 and log why. Args: pid, log, message, description.
expect_exit() {
    local rc=0
    for _ in {1..50}; do kill -0 "$1" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$1" 2>/dev/null; then
        kill -TERM "$1"
        wait "$1" || true
        fail "$4: tcxflow still running"
        return
    fi
    wait "$1" || rc=$?
    if [[ $rc == 1 ]] && grep -q "$3" "$2"; then
        ok "$4: tcxflow exited with status 1"
    else
        fail "$4: exit status $rc"
        cat "$2"
    fi
}

# --- a collector restarts: it must decode the first message it gets, though nothing follows -----
# A quiet interface: IPv6 off and a static neighbour, so the test's datagrams are its only flows,
# and the first message after the restart is the one with the record checked.
ip link add tcol netns "$DP" type veth peer name tcol-peer netns "$WAN"
if ((V6)); then
    nsx "$DP" sysctl -qw net.ipv6.conf.tcol.disable_ipv6=1
    nsx "$WAN" sysctl -qw net.ipv6.conf.tcol-peer.disable_ipv6=1
fi
nsx "$DP" ip addr add 10.77.0.1/24 dev tcol
nsx "$DP" ip link set tcol up
nsx "$WAN" ip link set tcol-peer up
nsx "$DP" ip neigh add 10.77.0.99 lladdr 02:00:00:00:00:99 dev tcol nud permanent
cat >"$WORK/restart.conf" <<EOF
netns            $DP
interface        tcol:out
collector        127.0.0.1:$PORT3
inactive-timeout 1
export-interval  0
socket           $WORK/restart.sock
EOF
datagram() { nsx "$DP" bash -c "printf x >/dev/udp/10.77.0.99/$1"; } # 29 bytes
mkdir "$WORK/before" "$WORK/after"
ip netns exec "$MGMT" nfcapd -b 127.0.0.1 -p "$PORT3" -w "$WORK/before" >/dev/null 2>&1 &
COLL=$!
PIDS+=("$COLL")
sleep 1
"${TCX[@]}" --config "$WORK/restart.conf" >"$WORK/tcxflow-restart.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
wait_started $DAEMON "$WORK/tcxflow-restart.log"
datagram 65001
sleep 3 # exported: the collector has the templates
kill -TERM $COLL
wait $COLL || true
datagram 65002
sleep 3 # exported into the void: the port unreachable error is now pending at tcxflow
ip netns exec "$MGMT" nfcapd -b 127.0.0.1 -p "$PORT3" -w "$WORK/after" >/dev/null 2>&1 &
COLL=$!
PIDS+=("$COLL")
sleep 1
datagram 65003
sleep 3 # the first message the restarted collector gets
kill -TERM $DAEMON
wait $DAEMON || true
kill -TERM $COLL
wait $COLL || true
GOT=$(nfdump -R "$WORK/after" -N -q -o 'fmt:%pkt %byt' 'proto udp and dst port 65003' | awk '{p += $1; b += $2} END {print p + 0, b + 0}')
if [[ $GOT == "1 29" ]] && grep -q 'collector 127.0.0.1:.*port unreachable' "$WORK/tcxflow-restart.log"; then
    ok "collector restarted: it decoded the first message"
else
    fail "collector restarted: got \"$GOT\" of the record that came first, expected 1 29"
    cat "$WORK/tcxflow-restart.log"
fi

# --- export-interval: a partly filled message waits, the final export still sends it ---------
sed -e "s|restart.sock|batch.sock|" -e "s|^export-interval.*|export-interval  60|" "$WORK/restart.conf" >"$WORK/batch.conf"
mkdir "$WORK/batch"
ip netns exec "$MGMT" nfcapd -b 127.0.0.1 -p "$PORT3" -w "$WORK/batch" >/dev/null 2>&1 &
COLL=$!
PIDS+=("$COLL")
sleep 1
"${TCX[@]}" --config "$WORK/batch.conf" >"$WORK/tcxflow-batch.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
wait_started $DAEMON "$WORK/tcxflow-batch.log"
sleep 2 # the initial templates are sent, they do not wait
datagram 65004
sleep 3 # the flow ended (inactive-timeout 1), its record waits in the open message
BATCHED=$("${TCX[@]}" --config "$WORK/batch.conf" stats | grep -c '^flows exported *0$' || true)
kill -TERM $DAEMON
wait $DAEMON || true
kill -TERM $COLL
wait $COLL || true
GOT=$(nfdump -R "$WORK/batch" -N -q -o 'fmt:%pkt %byt' 'proto udp and dst port 65004' | awk '{p += $1; b += $2} END {print p + 0, b + 0}')
if [[ $BATCHED == 1 && $GOT == "1 29" ]]; then
    ok "export-interval: record held back, sent by the final export"
else
    fail "export-interval: held back $BATCHED (expected 1), got \"$GOT\" (expected 1 29)"
    cat "$WORK/tcxflow-batch.log"
fi

# --- an interface replaced by one with the same name and index: the kernel detached tcxflow's
# links from the old one, so nothing is metered any more; tcxflow must notice and exit ------
nsx "$DP" ip link add trep type veth peer name trep-peer
REP=$(nsx "$DP" cat /sys/class/net/trep/ifindex)
cat >"$WORK/replace.conf" <<EOF
netns     $DP
interface trep
collector 127.0.0.1:$PORT1
socket    $WORK/replace.sock
EOF
"${TCX[@]}" --config "$WORK/replace.conf" >"$WORK/tcxflow-replace.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
wait_started $DAEMON "$WORK/tcxflow-replace.log"
# One ip process for both: done long before tcxflow's next check, which then finds the name and
# the index unchanged.
printf 'link del trep\nlink add trep index %s type veth peer name trep-peer\n' "$REP" | nsx "$DP" ip -batch -
expect_exit $DAEMON "$WORK/tcxflow-replace.log" "interface trep is gone" "interface replaced (index $REP)"

# --- an interface given twice, by name and by altname: refused at start ------------------
nsx "$DP" ip link property add dev trep altname trep-alt
"${TCX[@]}" --netns "$DP" -i trep:in -i trep-alt:out --collector "127.0.0.1:$PORT1" --socket "$WORK/alt.sock" \
    >"$WORK/tcxflow-alt.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
expect_exit $DAEMON "$WORK/tcxflow-alt.log" "interface trep-alt is the same as trep" "interface and its altname"

# --- the namespace is deleted: tcxflow must let go of it and exit with status 1 -----------
"${TCX[@]}" --config "$WORK/tcxflow.conf" >"$WORK/tcxflow-netns.log" 2>&1 &
DAEMON=$!
PIDS+=("$DAEMON")
wait_started $DAEMON "$WORK/tcxflow-netns.log"
ip netns del "$DP"
expect_exit $DAEMON "$WORK/tcxflow-netns.log" "network namespace /run/netns/$DP is gone" "namespace deleted"

if ((FAIL)); then
    "${NFDUMP[@]}" -o 'fmt:%pr %sap -> %dap in=%in out=%out %pkt %byt'
    cat "$WORK/tcxflow.log"
    echo "E2E TEST FAILED"
else
    echo "e2e test passed$( ((V6)) || echo ' (no IPv6 in this kernel: routed IPv6 checks skipped)')"
fi
exit $FAIL
