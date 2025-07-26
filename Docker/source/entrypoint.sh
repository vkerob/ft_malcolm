#!/bin/sh
set -eu

echo "[source] Network configuration..."

echo "[source] Adding entries to /etc/hosts..."
echo "172.31.42.254 gateway" >> /etc/hosts
echo "172.31.42.10 target" >> /etc/hosts

ip route del default || true

ip route add default via 172.31.42.254 dev eth0

echo "[source] Route configured via gateway 172.31.42.254"
echo "[source] Name resolution configured (gateway: 172.31.42.254, target: 172.31.42.10)"

exec "$@"
