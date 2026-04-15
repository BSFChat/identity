# Stage 1: Build
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make g++ git python3 ca-certificates libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN cmake -B /build \
    -DCMAKE_BUILD_TYPE=Release \
    -DGAMECHAT_IDENTITY_BUILD_TESTS=OFF \
    && cmake --build /build -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/BSFChat/identity
LABEL org.opencontainers.image.description="BSFChat identity service (OIDC)"
LABEL org.opencontainers.image.licenses=MIT

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bsfchat-id /usr/local/bin/
COPY config/bsfchat-id.example.toml /etc/bsfchat/identity.toml
COPY web/ /usr/share/bsfchat/web/

RUN mkdir -p /data/keys

EXPOSE 8480
VOLUME ["/data", "/etc/bsfchat"]

CMD ["bsfchat-id", "--config", "/etc/bsfchat/identity.toml"]
