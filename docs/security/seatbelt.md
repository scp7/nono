---
title: macOS Seatbelt
description: How nono uses Apple's Seatbelt sandbox on macOS
---

nono uses Apple's Seatbelt sandbox framework on macOS to enforce capability restrictions at the kernel level.

## What is Seatbelt?

Seatbelt is macOS's mandatory access control (MAC) framework. It's the same technology that sandboxes App Store applications and Safari. Seatbelt policies are enforced by the XNU kernel - they cannot be bypassed by userspace code.

## How nono Uses Seatbelt

nono generates a Seatbelt profile (a Scheme-like DSL) based on your capability flags, then calls `sandbox_init()` to apply it.

```c
// Simplified: what nono does internally
sandbox_init(profile_string, SANDBOX_NAMED, &error);
// After this call, restrictions are permanent for this process
```

## Profile Structure

A nono-generated Seatbelt profile looks like:

```scheme
(version 1)
(deny default)

; Allow read access to system paths (required for executables)
(allow file-read*
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/System")
    (subpath "/Library")
    (subpath "/Applications")
    (subpath "/private/var/db"))

; User-granted paths
(allow file-read* file-write*
    (subpath "/Users/luke/project"))

(allow file-read*
    (subpath "/Users/luke/.config"))

; Block sensitive paths (even if parent is allowed)
(deny file-read* file-write*
    (subpath "/Users/luke/.ssh")
    (subpath "/Users/luke/.aws")
    (subpath "/Users/luke/.gnupg"))

; Network (if --net-allow)
(allow network-outbound)
; Or if network not allowed:
; (deny network*)
```

## System Paths

nono allows read access to system paths required for running executables:

| Path | Purpose |
|------|---------|
| `/usr` | System binaries and libraries |
| `/bin` | Core utilities |
| `/System` | macOS system files |
| `/Library` | System-wide application support |
| `/Applications` | Installed applications |
| `/private/var/db` | System databases |

These are read-only - the sandboxed process cannot modify system files.

## Library Access

macOS applications often need access to `~/Library`:

| Path | Access | Purpose |
|------|--------|---------|
| `~/Library` | Read | Application preferences, caches |
| `~/Library/Caches` | Read+Write | Application caches |
| `~/Library/Logs` | Read+Write | Application logs |

## Sensitive Paths

nono explicitly denies access to credential storage, even if a parent directory is allowed:

```scheme
(deny file-read* file-write*
    (subpath "/Users/luke/.ssh")
    (subpath "/Users/luke/.aws")
    (subpath "/Users/luke/.gnupg")
    (subpath "/Users/luke/.kube")
    (subpath "/Users/luke/.docker")
    (literal "/Users/luke/.npmrc")
    (literal "/Users/luke/.netrc")
    (literal "/Users/luke/.gitcredentials")
    (literal "/Users/luke/.bash_history")
    (literal "/Users/luke/.zsh_history")
    (literal "/Users/luke/.bashrc")
    (literal "/Users/luke/.zshrc")
    (literal "/Users/luke/.profile")
    ; ... and more
)
```

## Network Control

Network access is allowed by default and controlled with a simple allow/deny:

```scheme
; Default (network allowed)
(allow network-outbound)
(allow network-inbound)
(allow network-bind)

; If --net-block is specified
(deny network*)
```

### Granular Filtering Limitations

While Seatbelt theoretically supports some network filtering capabilities (by port, protocol, etc.), it does **not** provide native per-hostname or per-domain filtering. This is a fundamental limitation of the Seatbelt framework.

Implementing granular network filtering would require one of these approaches:

1. **IP allowlists** - Resolve domains to IPs before sandboxing, then use Seatbelt's IP filtering. This is fragile (IPs change, CDNs use many IPs, DNS resolution happens outside sandbox).

2. **Application-layer proxy** - Run a filtering proxy that applications connect through. This adds complexity, requires proxy-aware applications, and the proxy itself runs with elevated permissions.

3. **Packet filtering integration** - Integrate with macOS's packet filter (pf) framework. This requires root privileges and conflicts with nono's design goal of not requiring sudo.

Each approach has significant technical challenges and security trade-offs. For now, nono uses binary network control (on by default, `--net-block` to disable entirely). Granular filtering support may be explored in future releases but requires careful experimentation.

## Irreversibility

Once `sandbox_init()` is called, the restrictions are permanent:

- There is no `sandbox_remove()` or `sandbox_expand()` API
- The process cannot modify its own sandbox
- All child processes inherit the restrictions
- The only way to escape is to exploit a kernel vulnerability

This is the core security guarantee.

## Debugging

If a command fails with permission errors:

1. Run with `--dry-run` to see what capabilities would be granted
2. Run with `-vvv` for verbose logging
3. Check Console.app for sandbox violation logs:
   - Filter by "sandbox" or your process name
   - Violations show the exact path and operation blocked

## Limitations

### macOS Version Support

Seatbelt is available on macOS 10.5+, but nono is tested on macOS 10.15 (Catalina) and later.

### App Sandbox Interaction

If nono itself is running inside an App Sandbox (e.g., from a sandboxed terminal), the restrictions stack. The inner sandbox cannot grant more permissions than the outer sandbox allows.

### Code Signing

Some macOS security features interact with code signing. If you build nono from source without signing, you may see Gatekeeper warnings. This doesn't affect sandbox enforcement.

## References

- [Apple Sandbox Design Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
- [sandbox_init man page](https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man3/sandbox_init.3.html)
- [XNU source code](https://github.com/apple-oss-distributions/xnu)
