# Deep Code Review Findings (Rust, Security, Structure)

Date: 2026-02-16
Repository: `nono`
Scope: `crates/nono`, `crates/nono-cli`, `bindings/c`, policy/config paths
Validation run:
- `cargo test --workspace --quiet` (all passing)
- `cargo clippy --workspace --all-targets --quiet` (warnings in tests)

## 1. CRITICAL: `openat2` requests are misparsed, allowing access-mode escalation via seccomp supervisor
- Severity: Critical
- Area: Linux supervised mode, seccomp notification handling
- Evidence:
  - `crates/nono-cli/src/exec_strategy.rs:1515`
  - `crates/nono-cli/src/exec_strategy.rs:1516`
  - `crates/nono-cli/src/exec_strategy.rs:1520`
  - `crates/nono/src/sandbox/linux.rs:342`
  - `crates/nono-cli/src/exec_strategy.rs:1636`
  - `crates/nono-cli/src/exec_strategy.rs:1638`
- Why this is a problem:
  - The seccomp filter intercepts both `openat` and `openat2`.
  - Handler derives access mode from `notif.data.args[2]` as if it were `openat` flags.
  - For `openat2`, `args[2]` is a pointer to `struct open_how`, not flags, so access classification is wrong.
  - This can result in injecting an fd opened with broader permissions than the syscall originally requested.
- Exploit path (high level):
  - Child issues `openat2` with read intent.
  - Supervisor misclassifies request as read-write and injects RW fd.
  - Child gains write capability unexpectedly.
- Actionable fix:
  1. Detect syscall kind (`openat` vs `openat2`) from `notif.data.nr`.
  2. For `openat2`, safely read `open_how.flags` from child memory and derive access from that value.
  3. Fail closed: if flags cannot be decoded, deny notification.
  4. Add tests proving no privilege broadening in `openat2` path.

## 2. HIGH: Initial-capability fast path loses file/dir semantics, enabling unintended subtree grants
- Severity: High
- Area: Linux supervised fast path
- Evidence:
  - `crates/nono-cli/src/exec_strategy.rs:855`
  - `crates/nono-cli/src/exec_strategy.rs:856`
  - `crates/nono-cli/src/exec_strategy.rs:1564`
- Why this is a problem:
  - Fast path stores only canonical paths in `initial_paths` and checks with `starts_with`.
  - File capabilities and directory capabilities are treated identically.
  - A file capability should allow only exact-file access, not descendants.
- Actionable fix:
  1. Store initial entries as `{ path, is_file }`.
  2. Match with `==` for files, `starts_with` for directories.
  3. Add regression test: file capability must not authorize `file/subpath`.

## 3. HIGH: Profile “signature” trust is presence-only; no cryptographic verification is enforced
- Severity: High
- Area: Profile loading / trust model
- Evidence:
  - `crates/nono-cli/src/profile/mod.rs:185`
  - `crates/nono-cli/src/profile/mod.rs:187`
  - `crates/nono-cli/src/profile/mod.rs:213`
  - `crates/nono-cli/src/profile/mod.rs:214`
  - `crates/nono-cli/src/config/verify.rs:21`
- Why this is a problem:
  - A profile is treated as “signed” if `meta.signature` is merely present.
  - The cryptographic verification module exists but is not integrated.
  - This bypasses the `--trust-unsigned` safety gate by adding any dummy signature string.
- Actionable fix:
  1. Require real signature verification for user profiles before treating them as trusted.
  2. Validate against explicit trusted keys from config.
  3. Reject invalid signatures exactly like unsigned profiles (default deny).
  4. Add tests: bogus signature must fail, valid minisign must pass.

## 4. MEDIUM: User profile path selection trusts `XDG_CONFIG_HOME` without validation
- Severity: Medium
- Area: Profile path resolution
- Evidence:
  - `crates/nono-cli/src/profile/mod.rs:242`
  - `crates/nono-cli/src/profile/mod.rs:243`
- Why this is a problem:
  - Unlike other env paths in codebase, this path is not validated as absolute/safe.
  - Relative or attacker-influenced values can redirect profile loading unexpectedly.
  - Combined with finding #3, this weakens profile trust boundaries.
- Actionable fix:
  1. Validate `XDG_CONFIG_HOME` as absolute and canonicalized.
  2. Optionally require owner-only directory/file permissions for trusted profile locations.
  3. Fall back safely when invalid.

## 5. MEDIUM: Dangerous command blocking is basename-only and easily bypassed
- Severity: Medium
- Area: Command policy enforcement
- Evidence:
  - `crates/nono-cli/src/config/mod.rs:92`
  - `crates/nono-cli/src/config/mod.rs:93`
  - `crates/nono-cli/src/config/mod.rs:105`
- Why this is a problem:
  - The check compares only `file_name()` to deny list entries.
  - Wrappers/symlinks/alternate binaries can bypass intended restrictions.
  - This is policy bypass (not sandbox boundary bypass), but relevant to “robust professional security”.
- Actionable fix:
  1. Resolve executable path before applying deny/allow command policy.
  2. Compare both canonical target basename and original invocation.
  3. Consider policy on interpreter-plus-script patterns (e.g., `python -c`, shell wrappers).

## 6. LOW: Structure complexity reduces security auditability
- Severity: Low
- Area: Layout/maintainability
- Evidence:
  - `crates/nono-cli/src/exec_strategy.rs` (very large multi-responsibility module)
  - `crates/nono-cli/src/main.rs:379` (large orchestration function)
- Why this matters:
  - Security-critical logic is spread across large functions with many platform branches.
  - Increases risk of subtle regressions and weakens reviewability.
- Actionable fix:
  1. Split execution logic into dedicated modules:
     - env sanitization
     - fork/exec plumbing
     - Linux seccomp supervisor
     - macOS shim supervisor
  2. Keep platform-specific logic behind narrow interfaces.
  3. Add explicit threat-model comments at module boundaries.

## 7. LOW (Idiomatic Rust): Clippy `ok().expect()` anti-patterns in tests
- Severity: Low
- Area: Rust idioms / test hygiene
- Evidence:
  - `crates/nono/src/supervisor/never_grant.rs:196`
  - `crates/nono/src/supervisor/socket.rs:425`
  - `crates/nono/src/supervisor/mod.rs:148`
- Why this matters:
  - Not a runtime/security risk, but reduces idiomatic quality and signal in tests.
- Actionable fix:
  1. Replace `result.ok().expect(...)` with `result.expect(...)`.
  2. Enable a stricter clippy profile in CI for test code as well.

## Strengths observed
- Good use of canonicalization and component-wise path checks in multiple security-sensitive paths.
- Explicit fail-closed behavior in many sandbox init and supervisor branches.
- Strong path sanitization for Seatbelt rule generation (`escape_path` with control-character rejection).
- Secure capability-state file creation (`create_new`, `0600`, bounded size validation).

## Recommended priority order
1. Fix finding #1 immediately (critical privilege broadening risk).
2. Fix finding #2 and #3 next (authorization boundary correctness).
3. Harden #4 and #5 for defense-in-depth.
4. Address #6 and #7 to improve long-term maintainability and review confidence.
