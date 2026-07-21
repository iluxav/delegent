# Build from the repository root: the gateway module depends on the protocol library one
# directory up (replace ../), so the build context must hold both modules.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
WORKDIR /src/gateway
RUN go build -trimpath -ldflags "-s -w" -o /out/delegent ./cmd/delegent

FROM alpine:3.20
RUN adduser -D -H delegent && apk add --no-cache ca-certificates
COPY --from=build /out/delegent /usr/local/bin/delegent
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data && chown delegent /data
USER delegent
ENV DELEGENT_HOME=/data
VOLUME /data
EXPOSE 8090
ENTRYPOINT ["docker-entrypoint.sh"]
