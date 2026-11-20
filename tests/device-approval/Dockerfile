# syntax=docker/dockerfile:1.7-labs
# Disposable test image only: never package/install its PAM or browser fixtures.
FROM rust:1.92.0-bookworm AS builder
WORKDIR /src
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends libpam0g-dev
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY assets/ assets/
COPY tests/device-approval/pam_gate.c /tmp/device-approval-pam.c
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --no-default-features --bins \
    && install -d /out \
    && install target/release/rbw target/release/rbw-agent /out/ \
    && cc -std=c11 -Wall -Wextra -Werror -fPIC -shared \
       /tmp/device-approval-pam.c -o /out/pam_howdy.so -lpam

FROM debian:bookworm-slim AS runtime
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
       ca-certificates libpam0g libpam-modules python3 python3-cryptography \
       python3-dbus python3-gi gir1.2-glib-2.0 dbus-daemon libglib2.0-bin \
       libnotify-bin util-linux tini \
    && useradd --create-home --uid 1100 --shell /bin/sh rbw \
    && install -d /usr/lib/security /opt/device-approval /artifacts \
    && touch /opt/device-approval/DISPOSABLE-ONLY
COPY --from=builder /out/rbw /out/rbw-agent /usr/local/bin/
COPY --from=builder /out/pam_howdy.so /usr/lib/security/pam_howdy.so
COPY tests/device-approval/harness.py tests/device-approval/notifications.py \
     tests/device-approval/pinentry.py /opt/device-approval/
# No browser claim: captures only the real production xdg-open invocation.
COPY tests/device-approval/open_url.py /usr/bin/xdg-open
RUN chmod 0755 /usr/bin/xdg-open /opt/device-approval/*.py \
    && chmod 0644 /usr/lib/security/pam_howdy.so
LABEL org.rbwbio.test.device-approval="1"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/bin/python3", "/opt/device-approval/harness.py"]
