FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    gcc \
    make \
	clang \
    bash \
    iputils-ping \
    iproute2 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY . /root/ft_malcolm

WORKDIR /root/ft_malcolm

RUN make

COPY Docker/source/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
