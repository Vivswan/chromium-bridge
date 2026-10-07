# 开发指南

本页介绍本地开发循环、工具链、测试与模糊测试的机制, 以及一次发布会改动的版本副本。分支、提交与合并的工作流见 [CONTRIBUTING.md](../../CONTRIBUTING.md); 项目为何采用当前这种形态, 见 [architecture.md](./architecture.md) 与 [security/rationale.md](./security/rationale.md)。

## 前置条件

[proto](https://moonrepo.dev/proto) 是引导阶段的工具链管理器: 安装一次, 把 `~/.proto/shims` 和 `~/.proto/bin` 加入 PATH, 然后在新检出的仓库里运行一次 `proto install`, 即可装好仓库根目录 `.prototools` 中固定的所有工具 (bun、moon、node、uv)。

Rust 只由 rustup 管理, 版本来自 `rust-toolchain.toml`, 所以新机器要先装 [rustup.rs](https://rustup.rs)。proto 刻意把 rust 留给 rustup: proto 的 rust 插件会注册一个工具链, 而 rustup 随后会误以为它已经安装。之后:

```sh
proto install    # provisions bun, moon, node, uv at the pinned versions (rustup owns rust)
moon run setup   # installs the bun workspace, the pinned Rust toolchain, and the crates; wires the git hooks (lefthook); the gate itself never installs
```

四个工具没有第一方 proto 插件, 需要手动安装一次: `cargo install cargo-nextest` (`moon run gate` 使用的测试运行器) 和 `brew install typos-cli cargo-machete actionlint` (只有 `moon run ci` 才运行的工具; typos 和 cargo-machete 也可以通过 `cargo install` 获得)。CI 从哪里获取它们:

- **`Containerfile` 以 `ARG <TOOL>_VERSION` 的形式固定这四个工具外加 cargo-deb**。CI 镜像携带这四个; cargo-deb 只安装在裸的发布与安装程序运行器上。
- **自行安装某个工具的作业通过 `bun scripts/pin.ts <tool>` 读取同一处固定版本**: checks.yml 的 tooling 作业读 cargo-machete (在镜像内, 该版本已经就位), `installers.yml` 与 `update-release.yml` 在各自的裸运行器上读 cargo-deb。
- **typos 和 actionlint 通过受管 ci.yml 的 fleet actions 运行**, 使用平台自己固定的版本, 所以本地版本偏差最多只会让某个发现提前浮现。

| 工具 | 用途 | 说明 |
|------|----------|-------|
| [proto](https://moonrepo.dev/proto) | 工具链引导 | 安装 `.prototools` 中固定的所有工具, 本地和 CI (`.github/actions/setup-moon`) 都是如此; 唯一一个还在别处出现的固定版本 (bun) 由 `moon run check-toolchain` 交叉核对 |
| [moon](https://moonrepo.dev) | 任务运行器 | 规范的命令接口: 每个开发任务都是一个 moon 任务。`moon run help` 列出全部任务; `moon run <task>` 运行其中一个 |
| Rust (cargo) | `chromium-bridge` 二进制 | 由 `rust-toolchain.toml` 固定 (权威的固定来源; rustup 和 IDE 都读它); `rustfmt` + `clippy` 组件, `cargo-nextest` 作为测试运行器 |
| bun | 所有 TypeScript 相关工作 | 包管理器、脚本运行器、扩展打包、TS 测试套件。固定在 `.prototools` 中 (并镜像到 `package.json` 的 `packageManager`) |
| node | vitest 测试套件 (`extension:test`、`web:test`) | 只固定在 `.prototools` 中; 由 proto 安装, 所以没有任何作业或镜像自行安装 |
| [`uv`](https://docs.astral.sh/uv/) | 协议 e2e 测试 | 安装仓库根目录 `.python-version` 中固定的那个 Python 版本, 所以本地运行和 CI 用同一个解释器。uv 自身只固定在 `.prototools` 中。这些测试套件只用标准库 |
| Chrome | DOM + 冒烟测试 | `CHROME_BIN` 可覆盖路径 |
| [`typos`](https://github.com/crate-ci/typos) + [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) | 拼写检查 + 未使用依赖门禁 | `moon run typos` / `moon run machete`; CI 在受管 ci.yml 中把 typos 作为门禁, 在 checks.yml 中把 machete 作为门禁 |
| [`actionlint`](https://github.com/rhysd/actionlint) | GitHub Actions 工作流 lint 门禁 | `moon run check-actions`; CI 在受管 ci.yml 的 actionlint 作业中运行它 |

Git 钩子由 [lefthook](https://lefthook.dev) 管理 (`lefthook.yml`): `moon run setup` 会接好一个运行 `moon run gate` 的 pre-commit 钩子, 即仓库自身工具链所能提供的检查; `moon run ci` 再加上只有 CI 才配备的工具。

## 目录布局

TypeScript 一侧是一个 bun 工作区, 根在仓库顶层 (`package.json` 的 `workspaces`), 只有一个 `bun.lock` 和一棵 node_modules 树。可构建的代码放在 `src/` 下 (apps 和 packages); 那里的每个目录都是 cargo 工作区或 bun 工作区的成员, 所以一个门禁就能编译整张图。TS 包把源码和测试分开放 (`src/` 和 `tests/`)。

```text
src/apps/host/           Rust binary "chromium-bridge" (thin argv dispatch over the library)
src/apps/extension/      MV3 extension (WXT); builds to build/extension (gitignored)
src/apps/web/            minimal Astro site rendering the repo's markdown docs (bun workspace member;
                         moon run web:build; not part of `moon run ci`)
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace: wire parsers + semantic validators
                         (nightly + libFuzzer; see the Fuzzing section below)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           the browser suites (run_all.ts lists them); integration_e2e.ts and
                         presence_exchange_test.ts run apart (bun workspace member; isolated Chrome only)
tests/interop/           the official MCP SDK client against the release binary (bun workspace member)
tests/harness/           harness-smoke: real harness CLIs in isolated config dirs
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, check-extension-id.ts,
                         check-docs-literals.ts, check-docs-policy.ts, build-repro.ts,
                         fuzz-smoke.ts, lib.ts, ...; unit tests in scripts/tests/
```

所有工具脚本都是用 bun 运行的 TypeScript, 放在 `scripts/` 下, 它是 bun 工作区的成员。moon 的 `script:` 或工作流的 `run:` 只保持为一串直线式的工具调用; 一旦需要控制流、输出解析或错误处理, 它就应该成为这里的一个脚本, 并在 `scripts/tests/` 中配有单元测试。

有两个脚本, `scripts/build-repro.ts` 和 `scripts/fuzz-smoke.ts`, 刻意只依赖 node 内置模块、保持自包含, 这样不需要 `bun install` 也能运行: 发布工作流在安装工作区之前就构建二进制, 而夜间模糊测试作业根本不安装工作区。

依赖由自动化的供应链检查把关, 没有手动逐 crate 审计的步骤; 各层检查及其各自捕获的问题见 [SECURITY.md](../../.github/SECURITY.md#dependency-supply-chain)。`moon run audit` 在本地重现 cargo-deny 这一关。

## 常用任务

moon 是规范的命令接口: 每个开发任务都是一个 moon 任务, `moon run help` 打印带描述的完整菜单 (原始 JSON: `moon query tasks`)。不带作用域的名字 (`moon run ci`) 解析到根项目; 按项目划分的任务写作 `project:task` (`moon run extension:build`)。

```sh
moon run build     # build everything (see below)
moon run dev       # dev everything: extension (WXT) + docs site (Astro) + a dev browser
moon run test      # rust tests (nextest + doctests) + protocol e2e
moon run ci        # THE GATE: the cross-platform CI steps (see below for what CI adds)
moon run release   # pre-release gate: version checks + full ci
moon run install   # build the release binary, then register it (doctor --fix)
moon run lint      # lint everything: clippy -D warnings + biome lint
moon run fmt       # format everything: cargo fmt + biome format
moon run fix       # auto-fix everything: biome check --write + cargo fmt
```

`moon run build` 用一条命令构建整个仓库: 对 `src/packages/shared` 做类型检查, 打包扩展 (先渲染图标), 构建文档站点, 对 `scripts/` 做类型检查, 并运行 `cargo build --workspace`。做了横切性改动之后, 用它来证明整张图仍然能编译。

`moon run ci` 按其 `deps` 列表声明的顺序运行跨平台门禁步骤:

| 步骤 | 任务 |
|------|-------|
| Rust | `core:fmt-check`、`core:lint` (每个 cargo 工作区各运行一次, 根工作区与模糊测试工作区)、`typos`、`machete`、`core:test`、`core:test-doc`、`core:test-loom`、`doc` |
| TypeScript | `typecheck`、`check-ts`、`shared:test`、`extension:test`、`extension:build` |
| 协议 | `test-e2e` |
| 卫生检查 | `hygiene` (下文的 bun 侧检查)、`check-refresh-lockfiles`、`test-fuzz` |
| 契约 | `check-gen`、`check-envelope`、`check-gen-isolation` |
| 工作流 | `check-yaml`、`check-actions` |

CI 在此之上还会运行更多: macOS 和 Windows 的 rust 矩阵、覆盖率、linux-install、对抗与混沌测试套件、互操作测试套件、浏览器测试套件、安装程序、web 构建, 以及各项审计 (见下文的 [CI 布局](#ci-布局))。

根 `package.json` 的 scripts 只是薄薄的别名, 所以两个入口共享同一套实现:

| `bun run ...` | moon 任务 |
|------|------|
| `build`、`gen`、`typecheck` | 同名任务 |
| `lint`、`format`、`format:check`、`check`、`test` | `lint-ts`、`fmt-ts`、`fmt-check-ts`、`check-ts`、`test-ts` |

仓库级动词一次覆盖所有语言: `moon run lint` 是 clippy 加 biome lint, `moon run fmt` 是 cargo fmt 加 biome format, `moon run test` 是 Rust 加协议 e2e。每个任务体都是一条你也可以手动运行的普通命令:

```sh
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
# the fuzz workspace is excluded from the root one, so its two checks run against its own manifest
cargo fmt --check --manifest-path src/packages/core/fuzz/Cargo.toml
cargo clippy --locked --manifest-path src/packages/core/fuzz/Cargo.toml --all-targets -- -D warnings
uv run --no-project --isolated tests/protocol/e2e.py
bun install
bun run tsc -p src/apps/extension        # one TS project; `moon run typecheck` covers them all
bun run biome ci . --error-on-warnings   # lint + format check, warnings fail (biome.jsonc)
bun run --cwd src/apps/extension build
```

按领域划分的完整任务菜单:

| 领域 | 任务 |
|------|-------|
| 聚合任务 | `build`、`test`、`ci`、`hygiene` (CI 的 hygiene 作业运行的 bun 侧检查; `ci` 依赖它)、`release`、`lint`、`fmt`、`fix` |
| 开发循环 | `dev`、`dev-web`、`extension:dev` |
| Rust | `core:fmt-check` (= `core:fmt-check-workspace` + `core:fmt-check-fuzz`)、`core:lint` (= `core:lint-workspace` + `core:lint-fuzz`)、`test-rust` (= `core:test` + `core:test-doc` + `core:test-loom`, 后者是在核心的 `loom` 特性下对中介 (broker) 引用计数做模型检查)、`doc`、`build-release`、`build-repro`、`typos`、`machete`、`audit` |
| 模糊测试工作区 | `fuzz-seeds`、`fuzz-smoke`、`check-fuzz-smoke`、`test-fuzz` (该工作区的 clippy 与 fmt 检查分别由 `core:lint-fuzz` 与 `core:fmt-check-fuzz` 执行) |
| TypeScript | `typecheck`、`test-ts` (= `shared:test` + `extension:test` + `web:test` + `check-harness-driver`)、`lint-ts`、`check-ts`、`fmt-ts`、`fmt-check-ts`、`extension:build`、`web:build` |
| 契约代码生成 | `gen` (= `gen-shared`)、`gen-icons`、`gen-architecture-map`、`check-gen`、`check-envelope`、`check-gen-isolation` |
| 协议测试套件 | `test-e2e`、`test-adversarial`、`test-chaos`、`check-uv` |
| 互操作测试套件 | `test-interop` (官方 MCP SDK v2 客户端对发布二进制的测试)、`harness-smoke` (真实的客户端程序 (harness) CLI, 隔离的配置目录; 旧时代打开方式的金丝雀测试) |
| 浏览器测试套件 | `test-browser`、`test-integration` (只用隔离的 Chrome; 从不进入 `ci`) |
| 版本管理 | `check-version`、`check-extension-id`、`check-refresh-lockfiles` |
| 仓库卫生 (`hygiene` 的依赖) | `check-version`、`check-extension-id`、`check-toolchain`、`check-pins`、`check-hasher`、`check-moon-edges`、`check-ignored`、`check-cjk`、`check-typography`、`check-fuzz-smoke`、`check-harness-driver`、`check-docs-literals`、`check-docs-policy`、`check-planning-refs`、`check-compose`、`check-ci-scripts`、`check-docs-probe`、`check-architecture`、`check-docs-locales` |
| 工作流 | `check-yaml`、`check-actions` |

`check-docs-probe` 让英文文档的每个段落和列表项都保持在 70 词以内, 并让它们点名的每条路径都真实存在。翻译页面 (位于 `zh-cn` 或 `zh-tw` 文档树下, 或根目录的 `README.<locale>.md`) 只探测路径和链接: 按空白切分的词数读不懂 CJK, 所以由英文页面承担词数上限, 而 `check-docs-locales` 让翻译树与它逐文件镜像。

## moon: 规范的命令接口

每个任务只有一个定义, 并声明其输入: 仓库级任务和运行手册放在根 `moon.yml` 中, 按项目划分的任务 (`core`、`shared`、`extension`、`web`) 放在各自代码旁边的 `moon.yml` 中。

CI 运行同样的任务: 仓库自有的 `.github/workflows/checks.yml` 凡是某步骤有对应任务的地方都调用 `moon run <task>`。Rust 操作系统矩阵保留原始的 cargo 动词, 而 `runInCI: false` 的测试套件 (如 `test-interop`) 直接调用, 因为 `CI=true` 时 moon 不会解析它们。

**门禁从不缓存。** 工作区默认让每个任务都不缓存 (`.moon/tasks/all.yml` 中的 `taskOptions.cache: false`): 一个能被缓存命中满足的门禁不是门禁, 因为一个错误的哈希会让未经验证的代码落地。moon 无法对被 gitignore 的输入 (比如生成的 `.wxt/tsconfig.json`) 做哈希, 而一个写错的 `hasher.ignorePattern` 会悄悄把被跟踪的文件从每一个哈希中剔除。

重新选择启用缓存的两个任务 (`web:build`、`shared:typecheck`) 不是门禁步骤。因此 `moon run ci` 总是完整执行整套测试, 并按其 `deps` 列表声明的固定顺序进行 (`runDepsInParallel: false`)。底层工具 (cargo、tsc、vite、bun) 保留各自的增量缓存, 所以热重跑依然很快。

除了统一的任务词汇之外, moon 还带来了什么:

```sh
moon run extension:build   # one task, one definition, used by dev + CI
moon run :test             # every project's test task
moon ci                    # affected-only, based on touched files - a LOCAL
                           # convenience for quick iteration, NEVER the gate
```

**契约边从不收窄。** Rust 核心是规范的跨进程契约, 所以 `shared` 和 `extension` 任务把整个 core crate、每个 `scripts/gen-*.ts` 脚本以及 cargo 清单都声明为输入: 即 `.moon/tasks/all.yml` 中的 `rust-contract` 文件组。

这个列表刻意过宽, 因为契约路径上的过期结果是这个仓库唯一不能接受的失败模式。编辑这些任务定义时, 加宽输入永远安全, 收窄输入永远不安全。

哪些内容不进入任何哈希:

- **生成和下载的输出** (target、build、.wxt、渲染出的图标、模糊测试语料库和产物) 列在 `.moon/workspace.yml` 的 `hasher.ignorePatterns` 中。新的被 gitignore 的输出目录也放在那里; 忘记添加只会导致过度失效, 不会导致过期。
- **任何被跟踪的文件都不得匹配某个模式:** `moon run check-hasher` (门禁的一部分) 证明这一点。
- **moon 自身的状态** 放在被 gitignore 的 .moon/cache 目录中; `rm -rf .moon/cache` 是重置按钮。

## 工具链固定 (proto)

`.prototools` 固定 proto 自身、bun、moon、node 和 uv; `proto install` 把它们全部装好, 而 rust 只通过 rustup 来自 `rust-toolchain.toml`。CI 以同样的方式安装, 通过一个复合 action `.github/actions/setup-moon`, 每个需要工具链的仓库自有作业都使用它:

1. `setup-bun` 安装 `.bun-version` 中的 bun, 只用来运行固定版本读取器。
2. `bun scripts/pin.ts proto` 读取 proto 自身的版本, 这是 `moonrepo/setup-toolchain` 唯一读不到的固定版本。
3. 该 action 安装 proto, 然后 `proto install` 安装 `.prototools` 中的工具 (它的 bun 装在第一个 bun 之上, 所以裸运行器上会有两个)。
4. 设置 `cargo: "true"` 后, `setup-rust-toolchain` 从 `rust-toolchain.toml` 安装 rust。

CI 镜像 (`Containerfile`) 在构建时运行同样的 `proto install`, proto 版本作为它唯一的构建参数传入 (`container-image.yml` 和 `scripts/compose-run.ts` 用 `bun scripts/pin.ts proto` 计算它)。在镜像内, 该 action 发现一切已就绪, 只会重新运行 `proto install`, 除非镜像发布后某个固定版本变动过, 否则这是一个空操作。

`bun scripts/pin.ts <tool>` 是 proto 存在之前读取固定版本的唯一读取器。它同时扫描两个所有者文件, 当某个工具在两个文件中都被固定、被固定两次或在哪里都没有被固定时报错; `bun scripts/pin.ts --all` 用同一条规则扫描两个文件中的每一个固定版本, 而 `moon run check-pins` (属于 `hygiene`) 运行这次扫描和读取器的单元测试:

| 工具 | 所有者文件 | 行的形式 |
|-------|------------|------------|
| proto、bun、moon、node、uv | `.prototools` | `tool = "x.y.z"` |
| cargo-nextest、typos、actionlint、cargo-machete (镜像的工具) 和 cargo-deb (发布与安装程序运行器的工具) | `Containerfile` | `ARG <TOOL>_VERSION=x.y.z` |

有一个固定版本还存在于第二个文件中, 如果两份副本不一致, 或者 `.prototools` 固定了 rust、启用了 proto 的 rust 或 python 插件, `moon run check-toolchain` (门禁和 CI 的 hygiene 作业的一部分) 就会失败:

- **bun**: 镜像到 `package.json` 的 `packageManager` 和由模板管理的 `.bun-version`。

uv 只固定在 `.prototools` 中, python 由 uv 管理: 协议测试套件通过 `uv run --no-project --isolated` 在 `.python-version` 固定的解释器下运行。proto 刻意从不安装 python (`.prototools` 中的 `settings.builtin-plugins`)。

## CI 布局

`checks.yml` 把每个关注点定义一次, 由受管 ci.yml 在 all-green 门禁内调用。Linux 作业在已发布的 CI 镜像内运行 (`ghcr.io/<owner>/<repo>-ci:latest`, 由 `container-image.yml` 从 main 构建)。

工作流级别的 `CI_IMAGE_TAG` 是唯一的开关: 空值会让每个作业都在裸运行器上用同一个复合 action 运行。

| 作业 | 运行内容 | 位置 |
|-----|------|-------|
| `image` | 把镜像标签解析为摘要一次, 这样每个作业固定的都是同一份内容 | 裸运行器 |
| `rust` | 在 ubuntu、macOS 和 Windows 上运行 clippy 和测试; fmt、loom 模型、rustdoc 以及模糊测试工作区的 fmt、clippy 和测试只在 Linux 上运行 | Linux 上用镜像, 其他平台用裸运行器 |
| `build-release` | `moon run build-release`, 上传供下面的测试套件使用 | 裸运行器, 这样二进制链接到运行器上较旧的 glibc, 在两种环境中都能运行 |
| `coverage` | `cargo llvm-cov`, 仅供参考 (`continue-on-error`, 无阈值) | 镜像 |
| `extension` | `typecheck`、`check-ts`、`shared:test`、`extension:test`、`extension:build`, 然后对构建出的清单运行 `check-extension-id` | 镜像 |
| `contract` | 先单独运行 `check-gen` (它会重写生成的模块), 然后是 `check-envelope`、`check-gen-isolation`、`check-refresh-lockfiles` | 镜像 |
| `hygiene` | `moon run hygiene` | 镜像 |
| `tooling` | `machete`, 使用 `Containerfile` 固定版本的 cargo-machete | 镜像 |
| `web` | `web:build`、`web:test` | 镜像 |
| `linux-install` | 先下载 `build-release` 的二进制, 再运行 `scripts/linux-registration.ts`: 在隔离的 HOME 和 XDG 目录下运行 `doctor --fix`、重新注册、多浏览器、`uninstall` | 裸运行器: 它只需要那个二进制和一个运行场景驱动脚本的 bun |
| `protocol` | 对下载的二进制运行 `e2e`、`adversarial` 和 `chaos` 测试套件 | 镜像 |
| `interop` | 官方 MCP SDK 客户端对下载的二进制的测试 | 镜像 |
| `browser` | 可复用的 `browser.yml` (输入 `chrome-version`), `nightly.yml` 也调用它 | 裸运行器, Chrome 来自 `setup-chrome` |
| `installers` | `installers.yml` 构建 .pkg、.deb 和 .msi, 并在各自的运行器上安装 | 各平台的运行器 |
| `audits` | `audits.yml`: 对根工作区和模糊测试工作区运行 cargo deny | 裸运行器 |

## 开发扩展

扩展基于 WXT 构建, 它生成清单 (包括固定的密钥) 并打包 `src/apps/extension/src/entrypoints/` 下的入口点。

```sh
bun install
bun run --cwd src/apps/extension dev       # WXT dev mode: rebuild on change
bun run --cwd src/apps/extension build     # production bundle
```

在 `chrome://extensions` (开发者模式) 中把 `build/extension/chrome-mv3` 作为未打包的扩展加载。单元测试 (`bun run --cwd src/apps/extension test`) 在 Vitest 上用 `fakeBrowser` 运行, 不需要真实浏览器。

## 测试

协议测试套件 (`tests/protocol/e2e.py`、`adversarial.py`、`chaos.py`) 以子进程方式驱动真实的发布二进制, 走真实的线路协议, 不需要浏览器: `moon run test-e2e` (在门禁中)、`test-adversarial`、`test-chaos`。

`tests/browser/run_all.ts` 中列出的浏览器测试套件共用一个运行器, CI 的 `browser.yml`、容器和 `moon run test-browser` 都调用它。它先构建扩展, 运行那些测试套件, 然后检查每个套件都留下了自己的 RAN 标记。下表最后一行单独运行:

| 测试套件 | 证明的内容 |
|-------|----------------|
| `dom_test.ts` | 每个内容脚本操作, 使用构建出的内容脚本 (`build/extension/chrome-mv3` 下的 content-scripts/content.js), 通过 CDP 注入到无头页面中 |
| `ext_test.ts` | 加载 `build/extension/chrome-mv3` 后 Service Worker 能启动 (puppeteer-core); `BB_EXT_DIR` 可指向另一个未打包的扩展 |
| `security_browser_test.ts` | 安全模型的浏览器侧那一半, 针对同一个已加载的扩展 |
| `webauthn_test.ts` | 主机的校验器所假设的关于 Chrome WebAuthn 客户端的事实, 用 CDP 虚拟认证器代替 Touch ID |
| `cancel_test.ts` | 来自替身主机的 `cancel` 帧被消费且从不被应答; 不在 Windows 上运行 |
| `presence_exchange_test.ts` | 端到端的 WebAuthn 交换: 两个隔离的 Chrome 对着真实的发布版主机。单独运行 (`moon run test-presence-exchange`); `run_all.ts` 中的 `suitesFor` 说明了原因 |

```sh
bun tests/browser/run_all.ts                           # builds the extension, then the suites
CHROME_BIN=/path/to/isolated/chrome bun tests/browser/run_all.ts
```

没有隔离的 `CHROME_BIN` 时运行器会跳过; 让跳过或空转的测试套件变成失败的两个 CI 开关只在 [`tests/README.md`](../../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome) 的 Safety 一节说明一次。`moon run test-integration` (`tests/browser/integration_e2e.ts`) 是可选的端到端运行: 真实二进制、隔离的 Chrome 和扩展一起运行。

## 在容器中运行门禁与浏览器测试套件

容器就是隔离本身: 它携带仓库固定版本的每一个门禁工具, 外加一个发行版的 Chromium, 而宿主机上的任何浏览器或进程都不在它的触及范围内。`Containerfile` 构建它; `compose.yaml` 运行它, 且只使用 `docker compose` 和 `podman compose` 都实现的 Compose Specification 子集 (门禁中的 `moon run check-compose` 保证这一点)。

| 任务 | 在容器内运行的内容 |
|------|---------------------------|
| `moon run ci-container` | `moon run ci` |
| `moon run test-browser-container` | `xvfb-run -a moon run test-browser`, 并设置 `BB_REQUIRE_BROWSER=1` 和 `BB_BROWSER_CANARY_DIR=/work/tmp/browser-canary`, 这样跳过或空转的测试套件会像在 CI 中一样失败, 并且 RAN 标记在宿主机上仍可读取 |
| `moon run shell-container` | 位于 `/work` 的交互式 `bash` |

Docker 是默认引擎; `CONTAINER_ENGINE=podman moon run ci-container` 可以切换。第一次运行会构建镜像 (需要几分钟, 只一次); 检出目录绑定挂载在 `/work`, 所以构建结果会像本地构建一样落在宿主机上被 gitignore 的 build 目录中。

命名卷把 Linux 产物挡在宿主机检出目录之外, 并让重跑保持温热; `docker compose down -v` (或 `podman compose down -v`) 会把它们全部删除:

| 卷 | 挂载点 | 内容 |
|--------|------------|-------|
| `cargo-registry` | `/home/ci/.cargo/registry` | 下载的 crate |
| `cargo-target` | `/work/target` | Linux 构建, 遮住宿主机的 target 目录 |
| `bun-cache` | `/home/ci/.bun/install/cache` | 下载的软件包 |
| `node-modules` | `/work/node_modules` | Linux 侧的安装 (入口点运行 `bun install --frozen-lockfile`) |
| `moon-cache` | `/work/.moon/cache` | 容器内运行的 moon 状态 |

Podman rootless 把宿主机用户映射为容器 root, 所以 `compose.podman.yaml` 添加了 `userns_mode: keep-id:uid=1000,gid=1000`, 改为把宿主机用户映射到镜像的用户; 当 `CONTAINER_ENGINE=podman` 时, 任务会传入该文件。手动运行 compose 需要任务所提供的同样一组信息 (`scripts/compose-run.ts`), 包括镜像唯一的构建参数:

```sh
env UID="$(id -u)" GID="$(id -g)" docker compose build --build-arg "PROTO_VERSION=$(bun scripts/pin.ts proto)" shell
env UID="$(id -u)" GID="$(id -g)" docker compose run --rm shell
# from a linked worktree, use the launcher instead: bun scripts/compose-run.ts shell
```

隔离守卫的容器例外只在 [`tests/README.md`](../../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome) 的 Safety 一节说明一次。

## 模糊测试

`src/packages/core/fuzz/` 是一个独立的 cargo 工作区 (cargo-fuzz + libFuzzer, nightly rust), 有十一个模糊测试目标。凡是存在正确性属性的地方, 目标都会断言该属性, 而不是只检查是否 panic。根工作区的 clippy 与 rustfmt 门禁也覆盖这个工作区, 使用根 lint 表的一份副本, 其例外由该工作区的 `Cargo.toml` 说明。

| 目标 | 模糊测试的对象 | 除不 panic 之外的判定依据 |
|---------|----------------|------------------------|
| `nm_frame`、`mcp_jsonrpc`、`handshake`、`attach` | 线路帧解码器 | 解码 -> 编码 -> 解码是恒等变换 |
| `bridge_envelope` | 内部桥接信封读取器, 作为原始值以及作为两种带类型的帧 | 无 (拒绝或解码, 三次) |
| `handshake_verify` | MAC 校验器和服务器接受路径 | 正确计算的 MAC 能通过校验 |
| `enclave_challenge` | 主机密钥质询消息构造器 | 只接受文档化的字段矩阵, 且被接受的消息能拆回它的各个字段 |
| `classify_frame` | 控制帧路由器 | 帧的 `type` 恰好是它被读取时的标签 |
| `registration_manifest` | 我方/外来清单及扩展指针的判定 | 任何不能被证明是我方的都是 `Foreign` |
| `policy_doc` | 策略存储的解析面 | serde 往返, 比较格对每一对都给出划分 |
| `webauthn_authdata` | WebAuthn authenticatorData 布局解析器, 并向证明对象和断言校验器喂入同样的字节 | 从已证明数据中解析出的凭据密钥经过其存储拼写后能往返一致 |

`handshake_verify` 通过内存 I/O 驱动完整的服务器握手。服务器为每次握手绑定新的 nonce, 所以静态的模糊响应在那里只能到达失败即关闭的拒绝路径; 接受路径由同一目标的 MAC 判定依据加上 `handshake.rs` 中的 socketpair 单元测试覆盖。

字节输入目标的函数体放在 crate 的库中 (`fuzz/src/targets.rs`); 每个 `fuzz_targets/<name>.rs` 二进制用 `fuzz_target!` 包装其中一个, 库的测试则在 stable rust 上对每一个生成的种子在进程内运行同样的函数体。

语义目标通过 core crate 的 `fuzzing` 特性访问私有函数: 默认关闭, 只由模糊测试工作区启用, 内容只是没有运行时行为的重导出。`--all-features` 确实会编译它; 隔离论证在于没有任何发布的二进制启用该特性, 且 fuzz crate 位于单独的工作区, 所以特性统一不可能把它拉进真实构建。

三个生命周期各异的目录, 加上失败报告:

- `fuzz/seeds/<target>/`: 被 gitignore, 由 `moon run fuzz-seeds` (`fuzz/src/seeds/`) 在每次模糊测试之前从生产类型生成。crate 的测试要求每个种子符合其标签, 所以种子不可能偏离生成它的类型。
- 正常路径种子经过真实的编码器: NDJSON 和 Native Messaging 写入器、记录信封的 `encode`、工具目录自己的参数 schema。
- 对抗种子是对正常路径种子的一步变异 (一个未知字段、边界加一、超出阶梯的版本、重复的键、截断的 base64), 并标注必须拒绝它的读取器。
- 结构化目标 (`handshake_verify`、`enclave_challenge`) 接受 `Arbitrary` 派生的输入, 其编码在不同 `arbitrary` 版本之间不稳定, 所以它们没有种子; 它们的回归用单元测试代替。
- `fuzz/corpus/<target>/`: 被 gitignore, 由模糊测试器生成。夜间 CI 通过 `actions/cache` 恢复并保存它, 所以探索成果在各次运行之间累积, 而不是每晚从零开始。
- `fuzz/dictionaries/`: 交给 libFuzzer 的 token 字典。`json_protocol.dict` (JSON 种子中的每个键和字符串值) 随种子一起生成并被 gitignore。
- `fuzz/failures/<target>/`: 被 gitignore, 每次 `fuzz-smoke.ts` 运行时清空重写。每个崩溃的目标一个目录, 存放一份 `report.md` (重放命令、种子、小输入的 base64 内嵌、固定指令) 加上崩溃输入的副本, 遵循 fleet 的失败报告契约 (fleet 仓库的 docs/fuzzer.md)。夜间作业的议题提交 action 消费这些内容。

在本地运行:

```sh
moon run fuzz-seeds        # regenerate fuzz/seeds/ and the JSON dictionary (fuzz-smoke runs this first)
moon run fuzz-smoke        # bun scripts/fuzz-smoke.ts: every target, bounded run
moon run test-fuzz         # every generated seed through its target in-process (in the ci gate)
moon run check-fuzz-smoke  # unit tests for the driver itself (in the ci gate)
```

冒烟测试需要 nightly 工具链加上 `cargo install cargo-fuzz`, 二者缺一时会打印消息并跳过。夜间作业传入 `--require-toolchain`, 把这种跳过变成失败: 被跳过的一晚不能被视作绿色并自动关闭跟踪议题。

- 目标来自 `cargo +nightly fuzz list`, 所以列表不可能偏离 `fuzz/Cargo.toml`。
- 工具链就绪时, 缺少生成的种子或字典的检出会被拒绝, 并提示要运行的任务 (`moon run fuzz-seeds`), 所以在新克隆上直接运行 `bun scripts/fuzz-smoke.ts` 会以 1 退出, 而不是在没有语料库的情况下模糊测试。
- 崩溃的目标不会中止整轮运行: 脚本写下该目标的失败报告, 继续下一个, 并在结束时如有任何失败则以 1 退出。
- `--seed=N` 固定 libFuzzer 的 PRNG, 以尽力实现确定性重跑; 崩溃输入文件仍是真正的复现材料, 因为持久化的语料库每晚都不同。
- 本地每个目标运行 30 秒。夜间运行给每个目标 120 秒, 并传入 `--cmin`, 它在缓存保存前最小化每个通过目标的语料库 (cmin 限制每个快照的大小; GitHub 的 LRU 缓存淘汰限制快照数量)。
- 要对单个目标做真正的持续攻坚, 在 `src/packages/core` 下运行 `cargo +nightly fuzz run <target>`, 不限时长。

夜间作业位于 `.github/workflows/nightly-fuzz.yml`, 它是 fleet 的 fuzzer 模块起始模板在本仓库的实例。浏览器测试和变异测试留在 `nightly.yml` 中, 它在自己的 `nightly-failure` 标签下走同样的生命周期, 但没有失败产物, 所以它的议题指向运行日志。

- 红色的一晚: 把 `fuzz/artifacts/` 和 `fuzz/failures/` 作为 `fuzz-failures-<attempt>` 产物上传, 根据报告创建或更新 `fuzz-nightly` 跟踪议题, 并对它派发自动指派。
- 绿色的一晚: 关闭已打开的议题。
- `workflow_dispatch` 接受 `seed` 和 `iterations`, 所以任何一晚的配置都可以按需重跑。

当一个崩溃被提交为议题时:

1. 用议题中的命令重放它 (下载产物, 或解码内嵌的 base64)。
2. 修复 bug。
3. 把该输入作为带标签的种子固定到生成器中 (`fuzz/src/seeds/`: 产生它的变异, 以及必须拒绝它的读取器), 或者对于两个结构化目标, 固定为单元测试, 并随修复一起提交。正是这个固定使得下一个绿色夜晚的自动关闭成为证据而非运气。

刻意不做模糊测试的部分及其原因:

- `allowlist.rs`、`trust.rs`、`ipc/lockfile.rs`: 纯粹的 `serde_json::from_slice` 到派生了 `deny_unknown_fields` 的结构体。对它们做模糊测试实际上是在测 serde_json 而非我们的代码; 负面单元测试已经固定了失败即关闭的行为。
- `enclave/pubkey.rs`: `EnclavePublicKey::from_x963` 只是一次长度检查加一次首字节检查, 不是点校验。太简单, 不值得一个目标。
- 中介语义: 由 loom 模型检查和 `tests/protocol/adversarial.py` 负责, 它们演练的是交错执行和恶意对端, 而不是字节解析。
- 在场签名: Security.framework 调用, 不是字节解析器。
- TypeScript 一侧 (生成的 Zod schema 和手写的信封非对称层): 这是范围上的决定, 不是声称这些代码已经过多人审阅。

规定: 在 Rust 核心的信任边界上新增或修改定制解析器或语义校验器的 PR, 必须新增或扩展一个模糊测试目标, 或者把排除项连同理由加入上面的列表。确切的规则及其适用范围见 [SECURITY.md](../../.github/SECURITY.md#security-relevant-changes-review-bar)。

供应链范围: 模糊测试工作区只在夜间 CI 中运行, 从不链接进发布的二进制, 其第三方直接依赖仅限于 `libfuzzer-sys`、`arbitrary` 和 `serde_json` (加上被测 crate `chromium-bridge-core` 自身); `derive_arbitrary` 通过 `arbitrary` 的 derive 特性传递引入。新的模糊测试依赖仍要经过审计工作流中对 `fuzz/Cargo.toml` 的 `cargo deny` 检查, 以及常规的 PR 评审。

## 日志

两种二进制模式都把日志写到 **stderr** (stdout 承载线路协议)。用 `BB_LOG` 设置级别:

```sh
BB_LOG=debug chromium-bridge          # verbose
BB_LOG=error chromium-bridge          # quiet
# default is info
```

## 发布

发布由 release-please 从绿色的 `main` 切出; 流水线 (草稿发布、打包矩阵、证明、发布) 见 [docs/release.md](./release.md)。发布 PR 是唯一的版本号变更点: 它在 `release-please-config.json` 中的 extra-files 会重写下面的每一份副本, 当某份副本或配置不一致时, `moon run check-version` 会让 CI 失败, 在发布 PR 自身上也是如此。

| 版本副本 | 谁读取它 |
|---|---|
| `Cargo.toml` 的 `[workspace.package] version` | 各 crate、打包作业的标签检查 |
| `src/apps/extension/package.json` 的 `version` | WXT 构建出的清单 (`scripts/lib.ts` 中的 `versionedJsonFiles`) |
