# The CI image compose.yaml runs. Every input is pinned (repository pin files read at build time, a
# digest, a Debian snapshot, the ARGs below), so the hash of the build inputs identifies the image.
# OCI instructions only, so buildah builds it too.
FROM docker.io/library/debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ARG DEBIAN_SNAPSHOT=20261006T000000Z
ARG RUSTUP_VERSION=1.29.1
ARG CARGO_BINSTALL_VERSION=1.25.1
ARG CARGO_NEXTEST_VERSION=0.9.146
ARG TYPOS_VERSION=1.50.3
ARG ACTIONLINT_VERSION=1.7.12
# checks.yml's tooling job installs the same cargo-machete on a bare runner, read from this line by
# scripts/pin.ts.
ARG CARGO_MACHETE_VERSION=0.9.2
# Declared here as the one pin owner; installed on the release and installers legs alone (bare ubuntu
# runners, read by scripts/pin.ts), never in this image.
ARG CARGO_DEB_VERSION=3.8.0
# No default: proto's own pin is .prototools's, and no script runs in here to read it. container-image.yml
# and scripts/compose-run.ts compute it with `bun scripts/pin.ts proto` and pass it in.
ARG PROTO_VERSION

# Chrome for Testing ships no Linux arm64 build; Debian's chromium does, and the isolation guard
# accepts it inside a container. build-essential: cargo needs a C linker. xvfb + xauth: the
# non-headless browser suites. iproute2: the adversarial suite enumerates listeners with `ss`. The
# snapshot is reached over http because the slim image has no CA bundle yet (apt verifies the archive
# signatures regardless).
#
# The snapshot's updates and security Release files lapse a week after the pin. Check-Valid-Until is
# off in apt.conf.d rather than per command because whatever runs apt-get in the finished image
# (checks.yml's taiki-e/install-action) reads the same lapsed files.
RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
        -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && test "$(grep -c "^URIs: http://snapshot.debian.org/archive/debian[-a-z]*/${DEBIAN_SNAPSHOT}$" /etc/apt/sources.list.d/debian.sources)" = "$(grep -c '^URIs:' /etc/apt/sources.list.d/debian.sources)" \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/snapshot-valid-until \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git unzip xz-utils \
        build-essential pkg-config iproute2 \
        chromium xvfb xauth fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# actionlint's release assets use Debian's architecture names (amd64, arm64).
RUN curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_$(dpkg --print-architecture).tar.gz" \
    | tar -xz -C /usr/local/bin actionlint

# safe.directory lives in the system gitconfig, not in GIT_CONFIG_* variables: moon runs git with a
# scrubbed environment, and the bind-mounted checkout is owned by the host uid, not ours.
RUN groupadd --gid 1000 ci \
    && useradd --uid 1000 --gid ci --create-home --shell /bin/bash ci \
    && mkdir -p /work && chown ci:ci /work \
    && git config --system safe.directory '*'

USER ci
# Explicit tool homes: compose may run the container as a uid other than 1000 (docker on Linux passes
# the host's), and the homes must still resolve.
ENV HOME=/home/ci \
    PROTO_HOME=/home/ci/.proto \
    CARGO_HOME=/home/ci/.cargo \
    RUSTUP_HOME=/home/ci/.rustup \
    BUN_INSTALL=/home/ci/.bun \
    PATH=/home/ci/.proto/shims:/home/ci/.proto/bin:/home/ci/.cargo/bin:/usr/local/bin:/usr/bin:/bin

# proto and rustup read these two files natively. --chown: COPY writes root-owned entries whatever USER
# is, and the ci user removes the directory below.
WORKDIR /tmp/pins
COPY --chown=ci:ci .prototools rust-toolchain.toml ./

# rustup owns rust: rust-toolchain.toml is its only pin (`rustup toolchain install` with no argument
# installs the file's toolchain, profile and components included), and .prototools deliberately leaves
# rust to it.
RUN curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/$(uname -m)-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
    && rm /tmp/rustup-init \
    && rustup toolchain install

# The installer is the release asset of the pinned version (it installs into PROTO_HOME/bin), not the
# unversioned script on moonrepo.dev.
RUN curl -fsSL "https://github.com/moonrepo/proto/releases/download/v${PROTO_VERSION:?build arg from bun scripts/pin.ts proto}/proto_cli-installer.sh" \
    | bash -s -- --no-modify-path \
    && proto --version \
    && proto install

RUN curl -fsSL "https://github.com/cargo-bins/cargo-binstall/releases/download/v${CARGO_BINSTALL_VERSION}/cargo-binstall-$(uname -m)-unknown-linux-gnu.tgz" \
    | tar -xz -C "${CARGO_HOME}/bin" \
    && cargo binstall --no-confirm --locked \
        "cargo-nextest@${CARGO_NEXTEST_VERSION}" \
        "typos-cli@${TYPOS_VERSION}" \
        "cargo-machete@${CARGO_MACHETE_VERSION}"

WORKDIR /work

# compose.yaml mounts named volumes at these paths; a volume inherits the mode of the directory it
# covers, and the tool homes must stay writable when the container runs as a uid other than 1000.
RUN rm -rf /tmp/pins \
    && mkdir -p /work/node_modules /work/target /work/.moon/cache \
        "${CARGO_HOME}/registry" "${BUN_INSTALL}/install/cache" \
    && chmod -R a+rwX /home/ci /work

# LEFTHOOK=0: the git hooks belong to the host checkout, and the git dir is mounted read-only.
ENV CHROME_BIN=/usr/bin/chromium \
    LEFTHOOK=0

# The node_modules and cargo-registry named volumes start empty and hold the Linux install, which the host's
# macOS or Windows install cannot stand in for, so every service installs and fetches before its command
# (the gate's package binaries run from node_modules/.bin and its cargo verbs --frozen; neither fetches).
ENTRYPOINT ["bash", "-euo", "pipefail", "-c", "bun install --frozen-lockfile && cargo fetch --locked && cargo fetch --locked --manifest-path src/packages/core/fuzz/Cargo.toml && exec \"$@\"", "container-entrypoint"]
CMD ["bash"]
