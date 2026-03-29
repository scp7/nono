# WSL2 Support — Implementation Record

## Environment

- **WSL2 distro**: Ubuntu 20.04
- **WSL2 kernel**: 6.6.87.2-microsoft-standard-WSL2
- **Landlock ABI**: V3 (filesystem only, no TCP filtering)
- **GCC**: 10 (upgraded from 9 to fix aws-lc-sys memcmp bug)
- **Branch**: `feat/wsl2-support`

---

## Track 1.1 — WSL2 Detection ✅

### What was done

**Library (`crates/nono/src/sandbox/linux.rs`)**:
- Added `is_wsl2()` — cached detection via `OnceLock`
  - Checks `/proc/sys/fs/binfmt_misc/WSLInterop` (filesystem indicator)
  - Checks `/proc/version` for "microsoft" or "WSL" kernel string
  - `WSL_DISTRO_NAME` env var is intentionally NOT trusted (caller-controlled, could be spoofed to disable security features on native Linux)
  - Result cached for process lifetime
- Added `Wsl2FeatureMatrix` struct with `detect()` and `summary()` methods
  - Reports availability of: `filesystem_sandbox`, `block_all_network`, `per_port_network`, `seccomp_notify`
- Re-exported through `sandbox/mod.rs` and `lib.rs`

**Unit tests (7)** in `linux.rs`:
| Test | Validates |
|------|-----------|
| `test_is_wsl2_does_not_panic` | No crash in any environment |
| `test_is_wsl2_consistent` | OnceLock returns stable results |
| `test_detect_wsl2_matches_indicators` | Agrees with kernel-controlled indicators |
| `test_wsl2_feature_matrix_detect` | Feature flags correct per environment |
| `test_wsl2_feature_matrix_summary_not_empty` | Summary text is meaningful |
| `test_wsl2_feature_matrix_filesystem_matches_landlock` | Matches `is_supported()` |
| `test_wsl2_per_port_matches_abi_v4` | Matches Landlock V4 probe |

**Integration tests (21)** in `tests/integration/test_wsl2.sh`:
| Section | Tests | Track |
|---------|-------|-------|
| WSL2 Detection | Setup reports WSL2, indicators present | 1.1 |
| Filesystem Sandbox | allow, write, read, deny outside path | 1.2 |
| Block-All Network | curl blocked, netcat blocked | 1.3 |
| Per-Port Filtering | Correctly rejected (no V4) | 1.3 |
| Supervised Mode | Default exec works on WSL2 | 1.2/1.4 |
| WSL2 Proxy Policy | Default rejects ProxyOnly (fail-secure), error mentions escape hatch, insecure_proxy policy accepted | 1.3 |
| Setup Reporting | Exits 0, platform/Landlock/kernel info | 1.4 |
| Direct Mode | wrap runs, output correct, exit codes | 1.2 |

**Test helpers** (`tests/lib/test_helpers.sh`):
- `is_wsl2()` — kernel-controlled detection (WSLInterop file or /proc/version)
- `skip_unless_wsl2()` — skip test unless on WSL2
- `skip_on_wsl2()` — skip test if on WSL2

**Dev tooling**:
- `scripts/wsl-dev.sh` — sync/build/test across Windows↔WSL2
  - Handles: setup, sync (git + uncommitted files via rsync), build, test, test-wsl2, ci, shell
  - Auto-installs: Rust, build-essential, pkg-config, libdbus-1-dev, gcc-10 (if needed)
  - Fixes CRLF line endings on shell scripts after sync
- `scripts/run-all-tests.sh` — runs all integration test suites with summary

### What we learned

1. **Basic supervised mode works on WSL2** — the `EBUSY` from `SECCOMP_RET_USER_NOTIF` only triggers when capability elevation or proxy filtering is active, not on the default supervised exec path
2. **Filesystem sandboxing is fully functional** — Landlock V1-V3 works identically to native Linux
3. **Block-all network works** — `SECCOMP_RET_ERRNO` has no conflict with WSL2's seccomp filter
4. **Per-port filtering correctly rejected** — Landlock V4 needs kernel 6.7+, WSL2 is on 6.6
5. **Existing test suite mostly passes** — 244/254 tests pass, 10 failures are all pre-existing (missing D-Bus keyring, macOS-only assertions, test fixture bugs), none WSL2-specific

---

## Track 1.1 (supplementary) — .gitattributes ✅

Windows Git converts LF→CRLF on checkout, which breaks shell scripts in WSL2 (`$'\r': command not found`). Added `.gitattributes` with `* text=auto eol=lf` to enforce LF globally.

---

## Track 1.2 — Skip seccomp notify on WSL2 ✅

**Goal**: Guard `install_seccomp_notify()` and `install_seccomp_proxy_filter()` calls with WSL2 check.

### What was done

**3 guard points:**

1. **`main.rs`** — capability elevation guard: if `--capability-elevation` is set on WSL2, force it to false and print warning. Warning is concise when the kernel banner already shows the docs URL, includes the URL otherwise (future-proofs for when WSL2 gets Landlock V4+).

2. **`main.rs`** — proxy fallback guard: if `ProxyOnly` network mode would need seccomp proxy filter on WSL2, **fail secure by default** (error). Profiles can opt in to degraded execution via `wsl2_proxy_policy: "insecure_proxy"`.

3. **`exec_strategy.rs`** — defense-in-depth guards on both `install_seccomp_notify()` and `install_seccomp_proxy_filter()` call sites in the child process post-fork. Uses `libc::write` (async-signal-safe). These should never be reached due to the main.rs guards.

**User-visible behavior:**

```
$ nono run --capability-elevation --allow /tmp -- echo "hello"
   kernel  Landlock V3 (File rename across directories (Refer), File truncation (Truncate))
          degraded: per-port filtering, capability elevation unavailable on WSL2
          (block-all network via --block-net still works)
          details: https://nono.sh/docs/cli/internals/wsl2
  [nono] WSL2: capability elevation disabled
  Applying sandbox... active
  hello
```

### Why seccomp notify fails on WSL2

WSL2's init process (PID 1) installs its own `SECCOMP_RET_USER_NOTIF` filter for Windows interop (mirrored networking mode). The Linux kernel only allows **one** user notification listener per filter chain. When nono tries to install a second one, it gets `EBUSY`. See [microsoft/WSL#9548](https://github.com/microsoft/WSL/issues/9548) (open since Jan 2023). Microsoft considers this intentional for mirrored networking — there is no fix timeline.

### Landlock ABI versions on WSL2

WSL2 kernel 6.6 supports Landlock V3. The ABI version determines available features:

| Landlock ABI | Kernel | Feature | WSL2 6.6 |
|-------------|--------|---------|----------|
| V1 | 5.13+ | Basic filesystem | ✅ |
| V2 | 5.19+ | File rename (Refer) | ✅ |
| V3 | 6.2+ | File truncation | ✅ |
| V4 | 6.7+ | TCP network filtering | ❌ |
| V5 | 6.10+ | Device ioctl filtering | ❌ |
| V6 | 6.12+ | Process scoping | ❌ |

Per-port network filtering requires V4. This will become available automatically when Microsoft upgrades the WSL2 kernel — no nono code changes needed since `detect_abi()` already probes for the highest available version.

---

## Track 1.3 — Network strategy on WSL2 ✅

**Goal**: Ensure all network modes work or fail secure on WSL2.

### What was done

The credential proxy **already runs out-of-process** (in the unsandboxed parent), so no architectural redesign was needed. However, a security regression was identified and fixed:

**Security regression (identified by code review):** On native pre-V4 Linux, `NetworkMode::ProxyOnly` is always kernel-enforced via seccomp notify. The initial WSL2 implementation silently disabled the seccomp fallback but still proceeded, leaving ProxyOnly unenforced — the child could bypass the proxy.

**Fix: `wsl2_proxy_policy` profile field** — ProxyOnly on WSL2 now **fails secure by default** with a clear error. Profiles must explicitly opt in to degraded execution:

```json
{
  "security": {
    "wsl2_proxy_policy": "insecure_proxy"
  }
}
```

| Policy value | Behavior |
|-------------|----------|
| `error` (default) | Refuse to run if ProxyOnly can't be kernel-enforced |
| `insecure_proxy` | Allow degraded execution with strong warning |

The policy enum, schema definition, merge logic, policy inspection tooling (`policy show`, `policy diff` in text and JSON), and profile authoring guide were all updated.

**Why alternative approaches weren't viable:**
- Unix socket proxy: HTTP clients need TCP for `CONNECT` tunnels; chicken-and-egg with blocked TCP
- Network namespaces / eBPF cgroup / iptables: all require root
- eBPF LSM: architectural mismatch (async hooks, no fd injection)
- ptrace: 100x+ overhead, breaks transparency, reintroduces TOCTOU races

**Future fix**: When Landlock V4 arrives, port-level lockdown activates automatically. Both policy values become equivalent. **Zero code changes needed.**

### Network mode summary on WSL2

| Mode | Works | Enforcement |
|------|-------|-------------|
| `--block-net` | ✅ | Kernel-enforced (seccomp `RET_ERRNO`) |
| Per-port filtering | ❌ Rejected | Needs Landlock V4 (kernel 6.7+) |
| `--credential` (default policy) | ❌ Rejected | Fails secure; error with instructions |
| `--credential` + `insecure_proxy` | ✅ Functional | Proxy works, child NOT port-locked |
| Default (allow all) | ✅ | No restriction |

---

## Track 1.4 — CLI UX ✅

**Goal**: Clear, accurate warnings and error messages for WSL2 limitations.

### What was done

**`setup --check-only` WSL2 feature matrix** (`setup.rs`):

```
  * WSL2 environment detected
    - Filesystem sandbox: available (Landlock V3)
    - Block-all network (--block-net): available
    - Per-port network filtering: unavailable (needs kernel 6.7+ for Landlock V4)
    - Credential proxy (--credential): requires wsl2_proxy_policy profile opt-in
    - Capability elevation (--capability-elevation): unavailable
    Note: seccomp user notification returns EBUSY (microsoft/WSL#9548)
```

**Kernel banner** (`output.rs`):

```
   kernel  Landlock V3 (File rename across directories (Refer), File truncation (Truncate))
          degraded: per-port filtering, capability elevation unavailable on WSL2
          (block-all network via --block-net still works)
          details: https://nono.sh/docs/cli/internals/wsl2
```

**Runtime warnings**: Concise `[nono] WSL2:` messages that omit the docs URL when the banner already shows it, include it otherwise.

---

## Track 1.5 — Documentation ✅

**Goal**: Compatibility matrix, seccomp limitation docs, workarounds.

### What was done

- `docs/cli/internals/wsl2.mdx` — comprehensive WSL2 documentation covering detection, Landlock ABI versions, seccomp notify limitation, `wsl2_proxy_policy` escape hatch, workarounds, future improvements
- `docs/cli/internals/wsl2-feature-matrix.mdx` — complete 110-feature compatibility matrix (78% full, 10% degraded, 12% unavailable)
- Link added to `docs/cli/internals/index.mdx`
- `nono-profile.schema.json` — `Wsl2ProxyPolicy` definition added
- `profile-authoring-guide.md` — `wsl2_proxy_policy` field documented
- `policy_cmd.rs` — field surfaced in `policy show` (human + JSON) and `policy diff` (text + JSON)

---

## Track 2.1 — Landlock V4 (kernel upgrade) 🔲

**No code changes needed.** ABI auto-detection already handles V4 when available. Depends on Microsoft upgrading WSL2 kernel from 6.6 to 6.7+.

---

## Track 2.2 — Supervisor alternatives 🔲

**Goal**: Evaluate eBPF LSM vs ptrace as alternatives to seccomp notify on WSL2.

**Status**: Evaluated, neither is viable for the nono supervisor architecture.

| Approach | Verdict | Reason |
|----------|---------|--------|
| eBPF LSM | Not viable | Async hook model — no synchronous syscall interception, no fd injection. Would require complete supervisor redesign. |
| ptrace | Not viable | 100x+ overhead, breaks transparency, reintroduces TOCTOU races, fragile fault handling. |
| LD_PRELOAD | Not viable | Bypassable by static binaries or direct syscalls. |
| Wait for MS fix | Recommended | microsoft/WSL#9548 — but Microsoft considers the seccomp filter intentional for mirrored networking. No fix timeline. |
| Landlock V4 | Best path | Automatic when kernel upgrades. No code changes needed. |

---

## Pre-existing test failures (not WSL2-related)

These failures exist on native Linux too:

| Suite | Failure | Cause |
|-------|---------|-------|
| `test_edge_cases.sh` (2) | relative path, `..` path | Binary path is relative, breaks when test cds |
| `test_learn.sh` (1) | learn traces cat | strace output format difference |
| `test_override_deny.sh` (1) | child profile inherits override_deny | Missing test fixture profile |
| `test_silent_output.sh` (1) | macOS keychain warning | macOS-only assertion on Linux |
| `test_trust_cli.sh` (5) | keygen, init, sign-policy | Missing `org.freedesktop.secrets` D-Bus service |
| `test_client_startup.sh` | npm install timeout | Infra/timing issue |
