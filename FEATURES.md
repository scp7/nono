# nono Feature Categories

> **New Category: Structural Confinement**
>
> nono defines a new category of AI agent security: **Structural Confinement**.
> Unlike guardrails (which can be linguistically bypassed) or policies (which rely on voluntary compliance),
> structural confinement makes unauthorized operations impossible at the kernel level. Security is not a
> layer that can be peeled away — it is a permanent, inheritable property of the process itself. Once
> applied, there is no API, no escape hatch, and no privilege escalation that can undo it.

---

## 1. Kernel Confinement

*The foundation: OS-enforced access control that cannot be bypassed from within.*

| Feature | Description |
|---------|-------------|
| **Landlock enforcement** | Linux 5.13+ filesystem access control at the syscall level |
| **Seatbelt enforcement** | macOS 10.5+ filesystem and network restrictions via `sandbox_init()` |
| **Irreversible application** | Once the sandbox is applied, there is no API to expand permissions — ever |
| **Child process inheritance** | All spawned processes inherit the same restrictions automatically |
| **No root required** | Runs without `CAP_SYS_ADMIN` or elevated privileges |
| **Capability-based model** | Permissions are explicitly granted capabilities, not denied lists; everything else is blocked |
| **Container compatible** | Works inside Docker, Podman, Kubernetes, Firecracker, and Kata without modification |

## 2. Credential & Secret Protection

*Secrets stay in the vault. The agent never sees, touches, or stores raw credentials.*

| Feature | Description |
|---------|-------------|
| **System keystore integration** | Credentials loaded from the OS keyring (macOS Keychain, Linux Secret Service) |
| **Environment variable injection** | API keys injected as env vars at runtime — keystore files never exposed to the agent |
| **Network-level credential injection** | Reverse proxy adds `Authorization` headers transparently; agent connects to `localhost` |
| **Zeroize memory handling** | Sensitive data wiped from memory after use via the `zeroize` crate |
| **Never-grantable paths** | System-critical credential paths (`.ssh`, `.gnupg`, `.aws`) blocked regardless of user approval |

## 3. Network Control

*Allowlist-only outbound access with hardcoded protection against metadata and internal network attacks.*

| Feature | Description |
|---------|-------------|
| **Host allowlist filtering** | Only explicitly allowed hosts are reachable; everything else is denied |
| **Hardcoded CIDR deny list** | Cloud metadata (169.254.169.254), RFC 1918 private ranges, and loopback always blocked |
| **DNS rebinding protection** | Hostnames resolved and all resulting IPs checked against deny list before connecting |
| **CONNECT tunnel** | HTTPS traffic tunnelled with end-to-end TLS; proxy never sees plaintext |
| **Enterprise proxy passthrough** | CONNECT requests chained through corporate proxies with deny list enforced as floor |
| **Session token authentication** | 256-bit random tokens with constant-time comparison prevent replay and timing attacks |

## 4. Recoverability & Integrity

*Content-addressable snapshots with cryptographic integrity, so every change is reversible.*

| Feature | Description |
|---------|-------------|
| **Content-addressable snapshots** | Working directory captured before execution using SHA-256 hashing |
| **Merkle tree commitments** | Cryptographic state commitment for tamper-evident integrity verification |
| **Interactive restore** | Review and restore individual files or the entire directory to a previous state |
| **Deduplication** | Identical file content stored once regardless of how many snapshots reference it |
| **Gitignore-aware exclusion** | Snapshot exclusion respects `.gitignore`, custom patterns, and glob filters |
| **Incremental snapshots** | Only changed files captured after the baseline, minimizing storage overhead |

## 5. Policy & Profiles

*Composable, auditable security policy built from reusable groups — one JSON file, many agents.*

| Feature | Description |
|---------|-------------|
| **Composable JSON policy groups** | Named groups define allow/deny rules; profiles compose groups by reference |
| **Built-in profiles** | Audited, minimal-permission profiles for Claude Code, OpenCode, and OpenClaw |
| **Destructive command blocking** | `rm`, `dd`, `chmod`, `sudo`, and other dangerous commands blocked before execution |
| **Per-invocation overrides** | CLI flags to selectively allow blocked commands or add paths for a single session |
| **Platform-aware deny handling** | Policy resolver accounts for macOS symlinks (`/etc` -> `/private/etc`) and Landlock ABI differences |
| **Learn mode** | `strace`-based path discovery that observes a real run and generates minimal permissions |

## 6. Supply Chain Trust

*Cryptographic attestation for instruction files — stop prompt injection at the source.*

| Feature | Description |
|---------|-------------|
| **Instruction file attestation** | CLAUDE.md, SKILLS.md, AGENT.md verified before the agent reads them |
| **Sigstore integration** | DSSE envelopes and in-toto statements for industry-standard signing |
| **Keyed and keyless signing** | Private key from system keystore, or keyless via OIDC + Fulcio + Rekor |
| **Trust policy** | Defines trusted publishers, known-malicious digest blocklist, and enforcement mode |
| **Transparency log** | Keyless signatures recorded in Rekor for public auditability |
| **Kernel-level enforcement** | Unverified instruction files blocked by Seatbelt deny rules (macOS) or seccomp-notify (Linux) |

## 7. Observability & Compliance

*Structured audit trails with cryptographic proof — every session is accountable.*

| Feature | Description |
|---------|-------------|
| **Structured JSON audit trail** | Every session records command, timestamps, exit code, and tracked paths |
| **Cryptographic snapshot commitments** | Merkle roots included in audit records for tamper-evident session history |
| **Diagnostic formatter** | Human-readable diagnostic output when sandboxed commands fail |
| **`nono why` tool** | Explains exactly why a specific path or operation would be blocked |
| **Dry-run mode** | Preview what would be sandboxed without executing the command |

## 8. Developer Experience

*Embeddable library, multi-language bindings, and first-class tooling for every workflow.*

| Feature | Description |
|---------|-------------|
| **Pure Rust library** | Policy-free sandbox primitive embeddable into any application |
| **Python bindings** | [nono-py](https://github.com/always-further/nono-py) via PyO3, published to PyPI |
| **TypeScript bindings** | [nono-ts](https://github.com/always-further/nono-ts) via napi-rs, published to npm |
| **C FFI** | Auto-generated `nono.h` header for integration with any language via `extern "C"` |
| **Interactive shell mode** | `nono shell` drops into a sandboxed shell for exploration and debugging |
| **Claude Code hooks** | Native hook integration for seamless Claude Code workflows |
| **Supervised mode** | Agent starts with minimal permissions; supervisor mediates expansion via fd injection |
| **Three execution strategies** | Direct (exec), Monitor (sandbox-then-fork), Supervised (fork-then-sandbox) |
