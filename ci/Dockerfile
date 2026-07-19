# CI image: mise (zig + just) + apk-tools 3.x for OpenWrt packages.
# Keep zig/just versions in sync with ../mise.toml.
# Build from repo root (need --load with buildx docker-container driver):
#   docker build --load -f ci/Dockerfile --tag registry.egoroff.spb.ru/zigcross:0.16 .
#   docker push registry.egoroff.spb.ru/zigcross:0.16
# Or build and push in one step:
#   docker build --push -f ci/Dockerfile --tag registry.egoroff.spb.ru/zigcross:0.16 .

ARG APK_TOOLS_VERSION=3.0.6

# --- apk-tools 3.x (mkpkg) — not in Debian repos ---
FROM debian:trixie-slim AS apk-tools
ARG APK_TOOLS_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        meson \
        ninja-build \
        pkg-config \
        libssl-dev \
        zlib1g-dev \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "v${APK_TOOLS_VERSION}" \
      https://gitlab.alpinelinux.org/alpine/apk-tools.git .
RUN meson setup build -Dprefix=/usr/local -Dlibdir=lib -Ddocs=disabled \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig \
    && apk --version | grep -F 'apk-tools 3.'

# --- final CI image ---
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        fakeroot \
        git \
        gzip \
        jq \
        libssl3t64 \
        tar \
        xz-utils \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=jdxcode/mise:latest /usr/local/bin/mise /usr/local/bin/mise
COPY --from=apk-tools /usr/local/bin/apk /usr/local/bin/apk
COPY --from=apk-tools /usr/local/lib/libapk.so* /usr/local/lib/
RUN ldconfig

ENV MISE_DATA_DIR=/mise \
    MISE_CONFIG_DIR=/mise \
    MISE_CACHE_DIR=/mise/cache \
    MISE_YES=1 \
    MISE_TRUSTED_CONFIG_PATHS=/ \
    PATH=/mise/shims:/usr/local/bin:/usr/bin:/bin

RUN printf '%s\n' \
      'export MISE_DATA_DIR=/mise' \
      'export MISE_CONFIG_DIR=/mise' \
      'export MISE_CACHE_DIR=/mise/cache' \
      'export PATH="/mise/shims:/usr/local/bin:$PATH"' \
      > /etc/profile.d/mise.sh

RUN mise use -g zig@0.16.0 just@1.46.0 \
    && zig version \
    && just --version \
    && apk --version | grep -F 'apk-tools 3.' \
    && command -v fakeroot

WORKDIR /workspace
