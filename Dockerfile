# BSFChat identity service (OIDC).
#
#   docker build -t bsfchat/identity .
#   docker run --rm -p 8480:8480 \
#     -v "$PWD/data:/data" -v "$PWD/identity.toml:/etc/bsfchat/identity.toml:ro" \
#     bsfchat/identity
#
# Kept deliberately in lockstep with server/Dockerfile: same base digest,
# same uid, same label set, same healthcheck shape. The two are deployed
# together by deploy/docker-compose.yml and a difference between them is a
# difference someone has to rediscover at 2am.

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
# Pinned by digest, not just by tag: `ubuntu:24.04` is a moving target, so
# a tag-only base means the image for v0.0.44 does not reproduce a month
# later. Digest obtained from `docker pull ubuntu:24.04` on 2026-09-17 —
# refresh it deliberately rather than letting it drift. Both stages use
# the same digest so the glibc the binary is linked against is the glibc
# it runs on.
FROM ubuntu:24.04@sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++ git python3 ca-certificates libssl-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG BSFCHAT_ID_VERSION=0.0.0-dev
ARG BSFCHAT_ID_REVISION=unknown

COPY . /src
WORKDIR /src

RUN cmake -B /build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DGAMECHAT_ID_BUILD_TESTS=OFF \
    -DBSFCHAT_ID_VERSION="${BSFCHAT_ID_VERSION}" \
    -DBSFCHAT_ID_REVISION="${BSFCHAT_ID_REVISION}" \
    && cmake --build /build -j"$(nproc)"

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04@sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9

ARG BSFCHAT_ID_VERSION=0.0.0-dev
ARG BSFCHAT_ID_REVISION=unknown

LABEL org.opencontainers.image.title="BSFChat identity"
LABEL org.opencontainers.image.description="BSFChat identity service (OIDC)"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.source=https://github.com/BSFChat/identity
LABEL org.opencontainers.image.url=https://bsfchat.com
LABEL org.opencontainers.image.version=${BSFCHAT_ID_VERSION}
LABEL org.opencontainers.image.revision=${BSFCHAT_ID_REVISION}

# curl is here for HEALTHCHECK, which needs to make a real HTTP request:
# a bash /dev/tcp probe only proves something accepted a TCP connection,
# which a wedged service with a full worker pool still does.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libsqlite3-0 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime, on the SAME fixed uid/gid as the chat server so one
# chown rule in deploy/setup.sh covers both bind mounts.
RUN groupadd --system --gid 10001 bsfchat \
    && useradd --system --uid 10001 --gid 10001 \
               --home-dir /data --shell /usr/sbin/nologin bsfchat

COPY --from=builder /build/bsfchat-id /usr/local/bin/
COPY config/bsfchat-id.example.toml /etc/bsfchat/identity.toml
COPY web/ /usr/share/bsfchat/web/

RUN mkdir -p /data/keys \
    && chown -R 10001:10001 /data \
    && chown -R 10001:10001 /etc/bsfchat

# The service resolves its web assets relative to the working directory.
WORKDIR /usr/share/bsfchat

USER 10001:10001

EXPOSE 8480

# /data holds the signing keys. An identity service that loses them
# invalidates every issued token, so this must be a real volume.
VOLUME ["/data", "/etc/bsfchat"]

# The OIDC discovery document: unauthenticated, cheap, and routed, so it
# fails if the HTTP server is up but routing is not. start-period covers
# first-start key generation, which is the slow part of a cold boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8480/.well-known/openid-configuration >/dev/null || exit 1

CMD ["bsfchat-id", "--config", "/etc/bsfchat/identity.toml"]
