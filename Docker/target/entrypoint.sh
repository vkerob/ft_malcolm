#!/bin/sh
set -eu

echo "[target] Network configuration..."

ip route del default || true

ip route add default via 172.31.42.254 dev eth0

echo "[target] Route configured via gateway 172.31.42.254"

exec "$@"
