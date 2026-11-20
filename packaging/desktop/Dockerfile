# syntax=docker/dockerfile:1.7-labs
# Rust's precompiled toolchain is copied, never compiled, into the Ubuntu linker/sysroot.
FROM rust:1.92.0-bookworm@sha256:5c38a9e735664861e84ce6918e98ce7f05dbac210230d45381bcf870b2d58083 AS toolchain
FROM ubuntu:22.04@sha256:45e9ddc6895604674618a409ca9f73d301da8fdb75fe330e8e9a27b3b219e4ad AS builder
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH \
    RBWBIO_DESKTOP_EXECUTABLE=/usr/bin/rbw \
    RUSTFLAGS="--remap-path-prefix=/src=."
COPY --from=toolchain /usr/local/cargo /usr/local/cargo
COPY --from=toolchain /usr/local/rustup /usr/local/rustup
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates libpam0g-dev pkg-config python3 dpkg-dev binutils
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY assets/desktop/ assets/desktop/
COPY LICENSE README.md ./
COPY packaging/desktop/package.py packaging/desktop/package.py
ARG SOURCE_COMMIT
ARG SOURCE_DATE_EPOCH
ENV SOURCE_COMMIT=$SOURCE_COMMIT SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
RUN --mount=type=cache,target=/root/.cache/rbwbio-face,sharing=locked \
    python3 packaging/desktop/package.py download
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --bins --target x86_64-unknown-linux-gnu \
    && python3 packaging/desktop/package.py package
FROM scratch AS artifact
COPY --from=builder /out/ /
