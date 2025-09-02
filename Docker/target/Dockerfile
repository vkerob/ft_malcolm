FROM alpine

RUN apk add --no-cache iproute2 bash curl

COPY Docker/target/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
