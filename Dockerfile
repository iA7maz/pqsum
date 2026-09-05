# syntax=docker/dockerfile:1
#
# pqsum container build.
#
#   dev     - full toolchain (rust, cmake, clang) for building and testing
#   builder - compiles a release binary from the working tree
#   runtime - minimal image shipping just the pqsum binary
#
# Build the CLI image:   docker build -t pqsum .
# Build the dev image:   docker build --target dev -t pqsum-dev .

ARG RUST_VERSION=1.90
ARG DEBIAN_RELEASE=bookworm

# --- dev -------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS dev

# liboqs is built from source by the `oqs-sys` crate, which needs cmake and a
# C toolchain; bindgen needs libclang.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        clang \
        libclang-dev \
        pkg-config \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Keep cargo's registry and the build directory inside the image so a bind
# mount of the source tree does not litter the host with root-owned files.
ENV CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/build

WORKDIR /work
CMD ["bash"]

# --- builder ---------------------------------------------------------------
FROM dev AS builder

COPY . .
RUN cargo build --release --locked \
    && install -Dm755 /build/release/pqsum /out/pqsum \
    && strip /out/pqsum

# --- runtime ---------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

LABEL org.opencontainers.image.title="pqsum" \
      org.opencontainers.image.description="Post-quantum cryptographic file verification utility" \
      org.opencontainers.image.source="https://github.com/iA7maz/pqsum" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

RUN useradd --create-home --uid 1000 pqsum
COPY --from=builder /out/pqsum /usr/local/bin/pqsum

USER pqsum
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/pqsum"]
CMD ["--help"]
