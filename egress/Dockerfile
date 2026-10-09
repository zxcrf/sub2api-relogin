FROM alpine:3.21
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf allowlist /etc/tinyproxy/
USER tinyproxy
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
