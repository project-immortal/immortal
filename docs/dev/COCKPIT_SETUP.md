<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Arafat Zahan (@kuasha420) -->
<!-- Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL) -->
<!-- Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework) -->

# Workstation Setup & Cockpit Bootstrap Runbook 🚀🖥️

This runbook documents the complete local workstation setup, toolchain requirements, cleanroom verification workflow, and Bring Your Own Data (BYOD) asset extraction procedures for **Project Immortal**.

---

## 1. Quickstart: Single-Command Developer Bootstrap

On modern Linux workstations (Ubuntu 22.04+, Arch Linux, Fedora 40+), bootstrap your environment and verify the cleanroom toolchain in one pipeline:

```bash
# Clone the repository and enter the workspace
git clone https://github.com/project-immortal/immortal.git
cd immortal

# Single-command environment bootstrap & verification
curl -sSf https://raw.githubusercontent.com/project-immortal/immortal/main/scripts/bootstrap.sh | bash || \
  (rustup update stable && cargo build --workspace && cargo test --workspace && agyis verify)
```

For fully hermetic manual bootstrap, proceed through the prerequisite checklist below.

---

## 2. Prerequisites & Toolchain Checklist

Ensure your development workstation meets the required system specifications and runtime environments:

| Component | Minimum Version | Installation / Verification Command | Purpose |
| :--- | :--- | :--- | :--- |
| **Operating System** | Linux x86_64 (Kernel 6.1+) | `uname -srm` (Ubuntu 22.04+, Arch, Fedora) | Wayland / X11 native development |
| **Rust Toolchain** | Rust 1.80.0+ | `rustup update stable && rustc --version` | Compiler, standard library, and runtime |
| **Rust Components** | clippy, rustfmt | `rustup component add clippy rustfmt` | Strict linting (`-D warnings`) & formatting |
| **Node.js** | Node.js v24+ | `node --version && pnpm --version` | Documentation automation & harness tooling |
| **Java Runtime** | OpenJDK 21 | `java -version` | AST analysis, Ghidra integration & schemas |
| **REA CLI** | REA CLI v6.8.0 | `rea --version` | Native cleanroom reverse engineering assistant |
| **mdBook Toolchain** | mdbook & mdbook-mermaid | `cargo install mdbook mdbook-mermaid` | Architectural documentation rendering |
| **Steam Paladins Path** | Paladins v8.1+ | See `PALADINS_INSTALL_PATH` below | BYOD asset extraction source |

### Setting Up the Steam Paladins Path

Project Immortal requires a valid, legally acquired installation of *Paladins: Champions of the Realm* via Steam. Define the installation directory in your environment:

```bash
# For default Steam library locations:
export PALADINS_INSTALL_PATH="$HOME/.steam/steam/steamapps/common/Paladins"

# For secondary or dedicated drive mounts:
# export PALADINS_INSTALL_PATH="/mnt/fast_data/games/SteamLibrary/steamapps/common/Paladins"

# Verify the ChaosGame asset directory exists:
ls -d "$PALADINS_INSTALL_PATH/ChaosGame/CookedPCConsole"
```

You can persist this variable in your user profile (`~/.bashrc`, `~/.zshrc`) or workspace `.env` file.

---

## 3. Running the Test Suite Hermetically

Project Immortal adheres strictly to **PSL-INV-001 (Universal Automated Verification Standard)**: tests must execute as fast and hermetically as possible without untracked network calls or state leakage.

### Fast Workspace Unit & Integration Tests

```bash
# Execute entire test suite across all workspace crates (asserting sub-second execution)
cargo test --workspace

# Run tests with backtrace on failure
RUST_BACKTRACE=1 cargo test --workspace -- --nocapture
```

The workspace suite completes across all crates (`immortal-core`, `immortal-extract`, `immortal-net`, `immortal-server`) in sub-second time (<0.10s).

### Strict Quality & Lint Gates

```bash
# Strict clippy check with warnings treated as hard errors
cargo clippy --workspace -- -D warnings

# Code formatting compliance
cargo fmt --all -- --check
```

---

## 4. Running Cleanroom Verification

Before committing changes or submitting pull requests, run the automated cleanroom verification gates to assert compliance with legal airlocks and obligation ledgers:

```bash
# Verify cleanroom specifications against schema rules
agyis verify --spec

# Run full project cleanroom audit and evidence validation
agyis verify
```

### Ledger Validation

The verification runner checks the following files:
- `.agents/ledger/obligations.json`: Validates that every reverse-engineered structure and protocol claim is mapped to an active obligation with explicit `evidence_criteria` and status `satisfied`.
- `.agents/ledger/manifest.json`: Ensures the manifest integrity matches the verified state with zero residual unproven claims.
- `.agents/ledger/evidence_bundle.json`: Confirms immutable sha256 cryptographic digests of dirty-room observations without storing copyrighted binaries in git.

---

## 5. Bring Your Own Data (BYOD) Asset Extraction Workflow

### The Inviolable BYOD Invariant

> [!IMPORTANT]
> **Zero Copyrighted Asset Distribution**: The Project Immortal repository contains zero proprietary meshes, textures, sound banks, or Unreal packages. All assets must be extracted locally from the developer's legally owned client.

### Extracting Local Assets

Run the extraction pipeline via `immortal-extract`:

```bash
# Extract CookedPCConsole packages into local assets directory
cargo run -p immortal-extract -- \
  --paladins-dir "$PALADINS_INSTALL_PATH" \
  --output-dir assets/extracted

# Extract specific champion assets (e.g. Fernando)
cargo run -p immortal-extract -- \
  --paladins-dir "$PALADINS_INSTALL_PATH" \
  --package "FERNANDO_ASSETS_SF.upk" \
  --output-dir assets/extracted/champions/fernando
```

Extracted assets are written directly to `assets/extracted/` which is ignored by `.gitignore`.

---

## 6. Building the Architectural Documentation

Build and preview the mdBook documentation locally:

```bash
# Build the static book
mdbook build docs

# Serve documentation with live reloading on http://localhost:3000
mdbook serve docs --open
```
