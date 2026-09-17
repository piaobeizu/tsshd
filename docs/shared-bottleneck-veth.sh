#!/usr/bin/env bash
# Disposable Linux network namespace demonstration; every device this script
# creates lives inside its own temporary namespaces — never on the host.
set -euo pipefail
mode=${1:-shared}
case "$mode" in shared|split|priority) ;; *) echo "usage: $0 shared|split|priority" >&2; exit 2;; esac
for bin in ip tc ping sysctl; do command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 1; }; done
(( EUID == 0 )) || { echo 'run as root (network namespace / qdisc privileges required)' >&2; exit 1; }
# Names are unique so parallel runs cannot collide. A stale namespace left by
# a crashed run (PID reuse) makes the preflight below refuse to start, and the
# trap deletes ONLY namespaces this invocation actually created — a
# pre-existing namespace is never removed.
tag="pf4${BASHPID}"
client="${tag}c"; server="${tag}s"; router="${tag}r"
for ns in "$client" "$server" "$router"; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        echo "refusing to run: namespace $ns already exists (stale from a crashed run?)" >&2
        exit 1
    fi
done
client_made=0; server_made=0; router_made=0
cleanup() {
    (( router_made )) && ip netns del "$router" 2>/dev/null || :
    (( client_made )) && ip netns del "$client" 2>/dev/null || :
    (( server_made )) && ip netns del "$server" 2>/dev/null || :
}
trap cleanup EXIT
ip netns add "$client"; client_made=1
ip netns add "$server"; server_made=1
ip netns add "$router"; router_made=1
# IPv6 is disabled inside the router namespace: the size filter below is
# IPv4-only, and kernel-generated IPv6/MLD packets would otherwise egress the
# IFBs at link-up and land in the HTB default class, making the asserted
# class counters nondeterministic.
ip netns exec "$router" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip netns exec "$router" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
# Both veth pairs are created INSIDE the owned namespaces and the router-facing
# ends are moved immediately, so no interface ever exists in the host namespace —
# including on failure: deleting the three namespaces removes every device.
ip netns exec "$client" ip link add ca type veth peer name ra
ip -n "$client" link set ra netns "$router"
ip netns exec "$server" ip link add sb type veth peer name rb
ip -n "$server" link set rb netns "$router"
for ns in "$client" "$server" "$router"; do ip -n "$ns" link set lo up; done
ip -n "$client" addr add 10.241.4.2/24 dev ca
ip -n "$server" addr add 10.241.5.2/24 dev sb
ip -n "$router" addr add 10.241.4.1/24 dev ra
ip -n "$router" addr add 10.241.5.1/24 dev rb
ip -n "$client" link set ca up; ip -n "$server" link set sb up
ip -n "$router" link set ra up; ip -n "$router" link set rb up
ip -n "$client" route add default via 10.241.4.1
ip -n "$server" route add default via 10.241.5.1
ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1
# Linux qdiscs are egress-only. Ingress from both sides is redirected to the SAME
# IFB in shared mode. Split mode redirects each side to a separate IFB. The
# packet is then reinjected to the router's ordinary forwarding path.
ip -n "$router" link add ifb0 type ifb
ip -n "$router" link set ifb0 up
if [[ $mode == split ]]; then
    ip -n "$router" link add ifb1 type ifb
    ip -n "$router" link set ifb1 up
fi
for entry in 'ra ifb0' "rb ifb$([[ $mode == split ]] && echo 1 || echo 0)"; do
    read -r iface target <<< "$entry"
    ip netns exec "$router" tc qdisc add dev "$iface" clsact
    ip netns exec "$router" tc filter add dev "$iface" ingress protocol ip pref 10 \
        matchall action mirred egress redirect dev "$target"
done
# netem models 50 ms one-way propagation, 2 Mbit/s serialization and a
# 1000-packet FIFO. No random loss: this isolates queue topology, not FEC.
if [[ $mode == priority ]]; then
    # Both directions still traverse one aggregate 2 Mbit/s parent. IPv4 total
    # length <256 (high byte zero) selects the reserved small-packet class.
    ip netns exec "$router" tc qdisc add dev ifb0 root handle 1: htb default 20
    ip netns exec "$router" tc class add dev ifb0 parent 1: classid 1:1 htb rate 2mbit ceil 2mbit
    ip netns exec "$router" tc class add dev ifb0 parent 1:1 classid 1:10 htb rate 128kbit ceil 2mbit prio 0
    ip netns exec "$router" tc class add dev ifb0 parent 1:1 classid 1:20 htb rate 1872kbit ceil 2mbit prio 1
    ip netns exec "$router" tc qdisc add dev ifb0 parent 1:10 handle 10: netem delay 50ms limit 100
    ip netns exec "$router" tc qdisc add dev ifb0 parent 1:20 handle 20: netem delay 50ms limit 1000
    ip netns exec "$router" tc filter add dev ifb0 parent 1: protocol ip pref 10 u32 \
        match u16 0x0000 0xff00 at 2 flowid 1:10
else
    ip netns exec "$router" tc qdisc add dev ifb0 root netem delay 50ms rate 2mbit limit 1000
fi
if [[ $mode == split ]]; then
    # Separate forward/reverse queues; do not mistake this for a shared 2 Mbit cap.
    ip netns exec "$router" tc qdisc add dev ifb1 root netem delay 50ms rate 2mbit limit 1000
fi
for target in ifb0 $([[ $mode == split ]] && echo ifb1); do
    ip netns exec "$router" tc qdisc show dev "$target"
done
# Bidirectional smoke test: routing and ingress redirect must work both ways.
ip netns exec "$client" ping -n -c 2 -W 3 10.241.5.2
ip netns exec "$server" ping -n -c 2 -W 3 10.241.4.2
if [[ $mode == priority ]]; then
    # Classification probes straddling the size boundary: ICMP payload 227
    # gives IPv4 total length 255 (small class 1:10); payload 228 gives 256
    # (bulk class 1:20).
    ip netns exec "$client" ping -n -c 2 -W 3 -s 227 10.241.5.2
    ip netns exec "$client" ping -n -c 2 -W 3 -s 228 10.241.5.2
fi
for iface in ra rb; do ip netns exec "$router" tc -s filter show dev "$iface" ingress; done
if [[ $mode == priority ]]; then
    stats=$(ip netns exec "$router" tc -s class show dev ifb0)
    echo "$stats"
    got10=$(awk '/class htb 1:10 /{f=1} f && /Sent/{print $4; exit}' <<<"$stats")
    got20=$(awk '/class htb 1:20 /{f=1} f && /Sent/{print $4; exit}' <<<"$stats")
    if [[ $got10 != 12 || $got20 != 4 ]]; then
        echo "class assertion failed: 1:10=$got10 pkt (want 12: 8 default-size + 4 of 255 B), 1:20=$got20 pkt (want 4: 256 B echo + replies)" >&2
        exit 1
    fi
    echo "class counters OK: 1:10=$got10 pkt (default-size + 255 B probes), 1:20=$got20 pkt (256 B probes)"
    ip netns exec "$router" tc -s filter show dev ifb0 parent 1:
fi
printf 'mode=%s OK (temporary namespaces removed on exit)\n' "$mode"
