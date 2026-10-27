# Security Policy 🛡️

Project Immortal takes the security and integrity of our software and community seriously. This policy outlines how to report vulnerabilities and our commitment to responsible disclosure.

---

## Supported Versions

Only the latest commit on the `main` branch of this repository receives active security fixes.

| Version / Branch | Supported |
| :--- | :--- |
| `main` | :white_check_mark: |
| Historical Releases (< 0.1.0) | :x: |

---

## Reporting a Vulnerability

If you discover a security vulnerability in Project Immortal, please **do not open a public issue**. Instead, follow responsible disclosure:

1. **GitHub Private Vulnerability Reporting**:
   - Use the "Report a vulnerability" button under the **Security** tab of the `project-immortal/immortal` repository.
2. **Direct Maintainer Contact**:
   - Email: **security@immortal.game** (or contact project maintainers via secure channels).

### What to Include
- Detailed description of the vulnerability and its potential impact.
- Step-by-step instructions or a minimal reproduction script to reproduce the issue.
- Affected crate(s) or modules (`immortal-server`, `immortal-net`, `immortal-extract`, `immortal-core`).
- Any suggested remediations or mitigations.

### Response Timeline
- **Initial Response**: Within 48 hours of report receipt.
- **Triage & Assessment**: Within 7 business days.
- **Fix & Advisory**: We will collaborate with the reporter to craft and test a fix before coordinated public disclosure.

---

## Scope & Out-of-Scope Items

### In Scope
- Memory corruption, denial of service, or remote code execution in `immortal-server` and `immortal-net`.
- Path traversal, buffer overflows, or malicious input decompression attacks in `immortal-extract`.
- Authentication bypass or credential spoofing in emulated auth gateways.

### Out of Scope (Will Not Be Accepted)
- **Official Game Servers**: Vulnerabilities or exploits affecting official Hi-Rez Studios / Evil Mojo servers or services. Project Immortal has no affiliation with or access to official live infrastructure.
- **Cheats & Matchmaking Bypasses**: Exploits designed to gain unfair competitive advantages on live official servers, or bypass EAC during official online matchmaking. Project Immortal is strictly an offline preservation and self-hosted server project.
- **Social engineering, phishing, or physical attacks** against project contributors.