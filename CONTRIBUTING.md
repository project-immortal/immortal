<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Project Immortal Contributors -->

# Contributing to Project Immortal 🛡️🤝

Thank you for your interest in contributing to **Project Immortal**! Our goal is to preserve *Paladins: Champions of the Realm* perpetually through cleanroom reverse engineering and server emulation.

Because Project Immortal operates in the domain of game preservation and protocol reconstruction, **legal hygiene and cleanroom discipline are paramount**. Every line of code in this repository must stand up to rigorous legal and technical scrutiny.

---

## 1. Cleanroom Contributor Attestation

Before submitting a Pull Request or issue containing protocol specifications, you must agree to the following Cleanroom Contributor Attestation:

> ### 📜 The Cleanroom Covenant
> 1. **Zero Proprietary Source Code**: I have never had access to, viewed, decompiled with internal symbols, or leaked proprietary source code belonging to Hi-Rez Studios, Evil Mojo Games, or Epic Games' proprietary modifications for *Paladins*.
> 2. **Cleanroom Airlock Separation**:
>    - **Dirty Room**: Binary reverse engineering, packet captures, decompiler analysis (Ghidra, REA), and disassembler views must remain strictly in isolated, untracked directories (`.rea/`, `dirty_room/`, `disassembly/`, `captures/`).
>    - **Clean Room**: Code authored in `crates/**` is written solely from cleanroom markdown specifications (`docs/specs/**`) and standard public RFCs.
> 3. **No Direct Copying**: I will never paste decompiled C++/UnrealScript code, raw proprietary symbol dumps, or proprietary binary blobs into cleanroom source code, issues, or pull requests.
> 4. **Typed Obligation Tracking**: When implementing new protocol structures or binary parsers, I will record the claim and verification criteria in `.agents/ledger/obligations.json`.

---

## 2. Developer Certificate of Origin (DCO)

Project Immortal requires that all commits be certified under the **Developer Certificate of Origin (DCO)**, Version 1.1:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it; and

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to Sign Off Your Commits
Add `-s` to your commit commands:
```bash
git commit -s -m "feat(extract): implement LZO chunk decompression table parser"
```
This appends a trailer line to your commit message:
```text
Signed-off-by: Jane Developer <jane@example.com>
```

---

## 3. Git Hygiene & Branching Strategy

Project Immortal follows a **Strict Trunk** model with protected `main`:

### Branch Naming Conventions
- `feat/<short-description>`: New functional features or crate implementations.
- `fix/<short-description>`: Bug fixes and defect remediations.
- `spec/<short-description>`: Cleanroom specifications or protocol RFCs.
- `docs/<short-description>`: Documentation, books, or architectural guides.
- `refactor/<short-description>`: Code restructuring without functional behavior changes.

### Conventional Commits
All commit messages must adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:
```text
<type>(<scope>): <short imperative summary>

[optional body]

Signed-off-by: Name <email>
```
Common scopes: `extract`, `net`, `server`, `core`, `spec`, `ci`, `deps`.

---

## 4. Local Pre-Commit Verification Gate

Before submitting a Pull Request, run the complete verification suite locally:

```bash
# 1. Run unit and integration tests
cargo test

# 2. Check formatting
cargo fmt --check

# 3. Lint with Clippy
cargo clippy -- -D warnings

# 4. Formally verify cleanroom specifications & obligations
agyis verify --spec
agyis verify
```

All 4 checks must pass cleanly with exit code 0.

---

## 5. Pull Request Process

1. Open your pull request against `main`.
2. Fill out the provided PR template, confirming:
   - [x] Cleanroom Contributor Attestation.
   - [x] DCO `Signed-off-by` on all commits.
   - [x] All local tests, clippy, and spec verification gates pass.
3. Address review feedback through contiguous, focused commits or rebased clean branches.
4. Once CI passes and reviewers approve, the PR will be merged via squash or rebase merge.
