#!/bin/sh
set -eu

sysctl -w net.ipv4.ip_forward=1

PUB_IF=$(ip -4 -o addr show scope global | awk '$4 ~ /^192\.168\.100\./ { print $2; exit }')

ip route show default >/dev/null 2>&1 || \
    ip route add default via 192.168.100.1 dev "$PUB_IF"

iptables -t nat -C POSTROUTING -o "$PUB_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$PUB_IF" -j MASQUERADE

echo "[gateway] Forwarding enabled, NAT via $PUB_IF"

exec "$@"