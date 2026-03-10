---
complexity:
  scope: L
  risk: High
  ambiguity: Med
  effort: 13
  rationale: This requires introducing Mac system extension logic and entitlement handling, which is tricky, crosses language boundaries, can impact main sandbox logic, and involves user-facing changes and opt-in, but the approach, while unfamiliar, is clear and can be scoped modularly.
---
# Plan

## Goal

Enable interception and on-demand approval/denial of I/O events in nono on MacOS using the Endpoint Security framework.

## Approach

Integrate MacOS Endpoint Security via a system extension, gated behind an opt-in flag or configuration. Develop a new component (likely in crates/nono/src/sandbox/macos_endpoint_security.rs) that communicates with the Endpoint Security API to monitor and control I/O operations, and update CLI/config to enable/disable this feature. Guide users about the required entitlement from Apple and system extension installation steps.

## Constraints
- Only supported on macOS 10.15+ with Endpoint Security entitlement (manual request to Apple required).
- Users must opt-in and install a system extension; default behaviour remains unchanged unless enabled.
- Changes must not break existing Seatbelt/standard Mac sandboxing (must coexist).
- Integration with CLI and config must be behind a clearly documented feature flag or config option.
- Initial implementation should focus on filesystem I/O events (e.g. open, write, create, delete), with extensibility for others.
- Implementation should degrade gracefully if entitlement is missing or system extension is not loaded.

## Subtasks

### task-1: Evaluate and document Endpoint Security entitlement requirements

Research the process for requesting and enabling the Endpoint Security entitlement on macOS, document prerequisites, and add a user-facing guide to a new markdown file.

**Acceptance criteria:**
- README-endpointsecurity.md is created with clear instructions and links for requesting entitlement and installing the system extension.
- README.md and CLI help reference the new documentation.

### task-2: Scaffold Endpoint Security integration module

Create a new Rust module (`macos_endpoint_security.rs`) that sets up the structure for Endpoint Security interactions, feature-gated for macOS and conditional compilation. Use the existing Apple APIs (via FFI or Rust crate) to allow stubbing functionality for unit testing.

**Acceptance criteria:**
- crates/nono/src/sandbox/macos_endpoint_security.rs exists and compiles (even if not fully implemented).
- Build only includes the module on macOS.
- Graceful runtime fallback if entitlement is missing.

### task-3: Implement basic Endpoint Security event interception and approval loop

Within the new module, implement monitoring for basic I/O events (open, write, create, delete) and allow for user-space callback to approve or deny actions. For this initial pass, just log events and simulate an allow/deny interaction.

**Acceptance criteria:**
- On supported macOS, the system can intercept and respond to I/O events (as shown via logging).
- Stub user approval/dismissal action flows are present (may be CLI-interactive or auto-allow at first).

### task-4: Wire up config flag and CLI to enable Endpoint Security extension

Add a configuration option and CLI flag to toggle Endpoint Security integration. Document that this requires opt-in and special privileges. The rest of the stack should fall back to existing behaviour if not enabled.

**Acceptance criteria:**
- Config and CLI can enable/disable Endpoint Security use.
- Help and config documentation updated for this feature.
- Opt-in by default (not enabled unless user asks).

### task-5: Integrate module with nono’s MacOS sandbox infrastructure

Update crates/nono/src/sandbox/macos.rs and mod.rs to delegate I/O interception to the new module if enabled, otherwise continue legacy path. Ensure new flow coexists with (but does not replace) existing Seatbelt sandboxing logic.

**Acceptance criteria:**
- I/O interception path determined by config/flag and platform checks.
- No changes for users who do not opt in; enabling Endpoint Security routes relevant events through new module.
- Seatbelt fallback path still functions.

### task-6: Update build system and documentation

Update Makefile and top-level documentation to reflect the new macOS requirements (system extension, entitlement, etc). Add build/test stubs as appropriate.

**Acceptance criteria:**
- Makefile documents/builds with the new extension steps where practical.
- README.md clearly documents how to enable and test Endpoint Security on macOS.
- CI/docs steps mention MacOS-specific limitations.


---

## Plan Review

*Reviewed by `plan-reviewer` at 2026-03-10 18:36:30 UTC*

**Verdict:** flag (confidence: high)

The plan demonstrates broad understanding and modular decomposition, but it omits key architectural and distribution complexities inherent in developing, distributing, and installing a privileged macOS Endpoint Security system extension—especially code-signing, packaging, IPC, and user interaction flows. The risks here are not just technical but regulatory (entitlement) and usability-related; without a dedicated system extension subtask and concrete user interaction/channel plan, the project is very likely to encounter rework and delivery delays.

### Concerns
- No discussion of privileged helper or system extension code-signing, which is mandatory for Endpoint Security extensions; this process is non-trivial.
- No explicit mention of how the system extension lifecycle (install, upgrade, removal, user approval) will be managed, which is critical and can block users.
- User-interactive approval flows for intercepted I/O events aren't fully scoped; relying on logging/stubs risks security and usability gaps.
- Testing and debugging guidance for low-level OS integration is absent, including recovery if the entitlement or extension fails.
- The integration between core app and the extension is underspecified (IPC, secure channel), which is a major complexity/risk area.
- Edge cases such as error propagation if the extension is not (or no longer) loaded at runtime are only vaguely mentioned.
- No mention of potential performance impact or how to minimize it when intercepting frequent I/O events.

### Suggestions
- Explicitly add a subtask for designing, implementing, signing, and packaging the system extension, clarifying user flows and requirements.
- Detail the secure communication mechanism between the extension and user-mode app (preferably using documented/best-practice IPC channels).
- Plan for robust error handling when the system extension or entitlement is unavailable, including fallback, user notification, and recovery.
- Specify at least a stub of the intended user approval UX (GUI, CLI prompt, etc), and how (and if) synchronous approval is possible per Apple's Endpoint Security constraints.
- Assess and document performance impact/tradeoffs, especially if monitoring high-frequency events.
- Add explicit testing, debugging, and recovery guidance, given the brittleness of system extension development on macOS.
