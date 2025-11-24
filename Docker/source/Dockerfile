FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    gcc \
    make \
	clang \
    bash \
    iputils-ping \
    iproute2 \
    tcpdump \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

COPY . /root/ft_malcolm

WORKDIR /root/ft_malcolm

RUN make re

COPY Docker/source/entrypoint.sh /entrypoint.sh
COPY Docker/source/get_params.sh /root/ft_malcolm/get_params.sh
RUN chmod +x /entrypoint.sh
RUN chmod +x /root/ft_malcolm/get_params.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
