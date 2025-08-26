FROM rust:alpine AS builder

WORKDIR /app

RUN update-ca-certificates
RUN apk add --no-cache openssl-dev openssl-libs-static musl-dev pkgconfig clang lld

COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --bin r2s-v2proxy --release --target x86_64-unknown-linux-musl && \
    mkdir -p /usr/local/bin && \
    cp target/x86_64-unknown-linux-musl/release/r2s-v2proxy /usr/local/bin/r2s-v2proxy

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/bin/r2s-v2proxy /r2s-v2proxy

ARG V2_SERVICE=ret2shell
ENV V2_SERVICE=${V2_SERVICE}

EXPOSE 1331

ENTRYPOINT ["/r2s-v2proxy"]
