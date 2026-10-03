# The CI image compose.yaml runs: every gate tool at the repository's pin, a distro Chromium for the
# browser suites, and nothing of the host in reach. The pin files are COPIED and read at build time, so
# the image cannot drift from them; the only versions written here are the four tools no pin file carries.
#
#   .prototools                     -> proto itself, then bun, moon, rust, uv via `proto install`
#   rust-toolchain.toml             -> channel, profile, components via `rustup toolchain install`
#   .github/workflows/checks.yml    -> cargo-machete (the pin CI's tooling job uses)
#   the ARGs below                  -> cargo-binstall, cargo-nextest, typos, actionlint, node
#
# OCI instructions only (no BuildKit syntax), a fully qualified base, and a non-root user, so docker and
# rootless podman build and run it alike. Chrome for Testing ships no Linux arm64 build; Debian's
# chromium does, and tests/browser/browser-safety.ts accepts it inside a container.
FROM docker.io/library/debian:trixie-slim

ARG CARGO_BINSTALL_VERSION=1.25.1
ARG CARGO_NEXTEST_VERSION=0.9.146
ARG TYPOS_VERSION=1.50.3
ARG ACTIONLINT_VERSION=1.7.12
ARG NODE_VERSION=24.21.0

# build-essential: cargo needs a C linker. xvfb + xauth: the non-headless browser suites.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl git unzip xz-utils \
    build-essential pkg-config \
    chromium xvfb xauth fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Node runs the vitest suites (`vitest run` scripts); no pin file provisions it and CI's runner image
# happens to carry one. Debian's package is too old for them, so the official build is installed.
RUN case "$(dpkg --print-architecture)" in amd64) node_arch=x64 ;; arm64) node_arch=arm64 ;; *) exit 1 ;; esac \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" \
    | tar -xJ -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'

# actionlint's release assets use Debian's architecture names (amd64, arm64).
RUN curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_$(dpkg --print-architecture).tar.gz" \
    | tar -xz -C /usr/local/bin actionlint

RUN groupadd --gid 1000 ci \
    && useradd --uid 1000 --gid ci --create-home --shell /bin/bash ci \
    && mkdir -p /work && chown ci:ci /work \
    && git config --system safe.directory '*'

USER ci
# The tool homes are named explicitly so they resolve for whatever uid compose runs the container as
# (docker on Linux passes the host's), not only for the image's own user.
ENV HOME=/home/ci \
    PROTO_HOME=/home/ci/.proto \
    CARGO_HOME=/home/ci/.cargo \
    RUSTUP_HOME=/home/ci/.rustup \
    BUN_INSTALL=/home/ci/.bun \
    PATH=/home/ci/.proto/shims:/home/ci/.proto/bin:/home/ci/.cargo/bin:/usr/local/bin:/usr/bin:/bin

WORKDIR /tmp/pins
COPY .prototools rust-toolchain.toml ./
COPY .github/workflows/checks.yml ./checks.yml

# rustup first: proto's rust plugin drives rustup rather than installing it, and only rustup reads the
# profile and components in rust-toolchain.toml (`rustup toolchain install` with no argument installs
# the file's toolchain).
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none \
    && rustup toolchain install

# proto's own pin is read before proto exists, so a TOML-tolerant scan; exactly one pin may match.
RUN proto_version="$(sed -nE 's/^proto[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' .prototools)" \
    && test "$(printf '%s\n' "${proto_version}" | grep -c .)" = 1 \
    && curl -fsSL https://moonrepo.dev/install/proto.sh | bash -s -- "${proto_version}" --no-profile --yes \
    && proto install

# cargo-binstall fetches the prebuilt tools (and compiles one when no build exists for this arch).
# The machete pin is the `tool:` input of checks.yml's install-action step, read as YAML so a comment
# or a look-alike cannot stand in for it; exactly one distinct pin may exist.
RUN curl -fsSL "https://github.com/cargo-bins/cargo-binstall/releases/download/v${CARGO_BINSTALL_VERSION}/cargo-binstall-$(uname -m)-unknown-linux-gnu.tgz" \
    | tar -xz -C "${CARGO_HOME}/bin" \
    && machete="$(bun -e ' \
        const jobs = Object.values(Bun.YAML.parse(await Bun.file("checks.yml").text()).jobs); \
        const tools = jobs.flatMap((job) => job.steps ?? []).map((step) => step.with?.tool); \
        const pins = new Set(tools.filter((tool) => typeof tool === "string" && tool.startsWith("cargo-machete@")).map((tool) => tool.slice("cargo-machete@".length))); \
        if (pins.size !== 1) throw new Error(`checks.yml must pin cargo-machete exactly once, found: ${[...pins].join(", ") || "none"}`); \
        console.log([...pins][0]);')" \
    && cargo binstall --no-confirm --locked \
        "cargo-nextest@${CARGO_NEXTEST_VERSION}" \
        "typos-cli@${TYPOS_VERSION}" \
        "cargo-machete@${machete}"

WORKDIR /work

# compose.yaml mounts named volumes at these paths; a volume inherits the mode of the directory it
# covers, and the tool homes must stay writable when the container runs as a uid other than 1000.
RUN rm -rf /tmp/pins \
    && mkdir -p /work/node_modules /work/target /work/.moon/cache \
        "${CARGO_HOME}/registry" "${BUN_INSTALL}/install/cache" \
    && chmod -R a+rwX /home/ci /work

COPY scripts/container-entrypoint.sh /usr/local/bin/container-entrypoint

# LEFTHOOK=0: the git hooks belong to the host checkout, and the git dir is mounted read-only.
# safe.directory lives in the system gitconfig above, not in GIT_CONFIG_* variables: moon runs git
# with a scrubbed environment, and the bind-mounted checkout is owned by the host uid, not ours.
ENV CHROME_BIN=/usr/bin/chromium \
    LEFTHOOK=0

ENTRYPOINT ["container-entrypoint"]
CMD ["bash"]
