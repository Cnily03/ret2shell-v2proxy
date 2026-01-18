FROM rust:alpine AS builder

WORKDIR /app

RUN update-ca-certificates
RUN apk add --no-cache openssl-dev openssl-libs-static musl-dev pkgconfig clang lld curl upx

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --bin r2s-v2proxy --release --target x86_64-unknown-linux-musl && \
    upx --best --lzma target/x86_64-unknown-linux-musl/release/r2s-v2proxy && \
    mkdir -p /usr/local/bin && \
    cp target/x86_64-unknown-linux-musl/release/r2s-v2proxy /usr/local/bin/r2s-v2proxy

FROM alpine:latest AS healthcheck

RUN apk add --no-cache clang lld upx make sudo
WORKDIR /app
COPY healthcheck/ .
RUN make ultra && make install

FROM scratch

COPY --from=healthcheck /usr/local/bin/healthcheck /usr/local/bin/healthcheck
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/bin/r2s-v2proxy /r2s-v2proxy

ARG LISTEN_PORT=1331
ENV LISTEN_PORT=${LISTEN_PORT}

ARG V2_SERVICE=ret2shell
ENV V2_SERVICE=${V2_SERVICE}

HEALTHCHECK --interval=5m --timeout=3s --start-period=10s --retries=1 \
    CMD healthcheck http://localhost:${LISTEN_PORT}/health

EXPOSE ${LISTEN_PORT}

ENTRYPOINT ["/r2s-v2proxy"]
