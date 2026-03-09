---
complexity:
  scope: M
  risk: Med
  ambiguity: Low
  effort: 5
  rationale: Clear bugfix affecting core execution/audit logic and CLI parsing, requiring moderate refactor but has well-defined boundaries and is testable with present coverage.
---
# Plan

## Goal

Always persist an audit session for every sandboxed execution, regardless of rollback or writable tracked paths.

## Approach

Refactor the CLI execution logic in crates/nono-cli/src/main.rs to decouple audit session creation from rollback state and tracked paths: always create a session directory and write audit metadata (session.json) for every execution, unless explicitly opted-out via a new --no-audit flag. Ensure network/file/command info, start/end time, and exit code are captured even when no writable paths exist or rollback is off.

## Constraints
- Maintain backwards compatibility with audit listing commands.
- Session audit must not require writable tracked paths or rollback state.
- Only skip audit session if new --no-audit flag is passed.
- Rollback implementation and snapshots remain conditional on writable tracked paths.

## Subtasks

### task-1: Add --no-audit CLI flag and parsing

Extend flag parsing to add a hidden/internal --no-audit switch to all subcommands that execute sandboxed commands. Document it in help output. Default audit is ON.

**Acceptance criteria:**
- CLI accepts --no-audit and toggles internal audit boolean.
- --no-audit appears in help text.
- Unit test ensures default is audit ON and --no-audit disables.

### task-2: Refactor main.rs to decouple audit from rollback logic

In crates/nono-cli/src/main.rs, move audit session directory creation and metadata writing (session.json) outside of rollback state/tracked_paths conditionals. It must run for every execution unless --no-audit is set.

**Acceptance criteria:**
- The audit session is always created (except with --no-audit).
- It occurs for all cases: rollback (with/without writable paths), supervised/default, and Monitor mode (if present).
- No dependency on tracked_paths or rollback_state for audit logic.

### task-3: Ensure session audit captures full execution context

Ensure all available info (command line, tracked paths, start/end, result, network audit/log events) is written into the session.json, matching or supersetting current detail, regardless of whether rollback is active.

**Acceptance criteria:**
- Audit file is complete even when tracked_paths/writable=0.
- Command, times, network, exit code fields always present.
- Regression tests verify structure and detail of audit entries.

### task-4: Update audit_commands and audit listing to support all session types

Revise audit_commands logic (e.g., nono audit list) to ensure it lists all sessions, regardless of rollback or writable paths. Ensure new logic is compatible.

**Acceptance criteria:**
- nono audit list shows sessions for all executed commands (excluding --no-audit).
- Filters, dates, and field output continue to work.
- Unit tests verify listing of formerly-skipped session types.

### task-5: Document the auditing change

Update CLI README.md to document the new always-on audit system and mention how to opt out.

**Acceptance criteria:**
- README documents always-on audit and --no-audit opt out.
- Usage examples shown for both behaviors.

### task-6: Test matrix regression and add/expand integration tests

Update/expand env_vars.rs and CLI integration tests to cover all the listed test matrix cases and the new audit persistence guarantee.

**Acceptance criteria:**
- Tests demonstrate sessions are created for all execution types.
- Confirm audit is skipped only with --no-audit.
- Tests for regression of original issue.
