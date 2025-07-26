FROM alpine
RUN apk add --no-cache iproute2 iptables
COPY Docker/gateway/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]

# ip link set dev eth1 down