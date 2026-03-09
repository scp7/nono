---
complexity:
  scope: M
  risk: Med
  ambiguity: Low
  effort: 5
  rationale: Touches main CLI orchestration and audit/rollback logic (about 5-6 files), but the conceptual change is straightforward, risk is moderate due to audit/rollback coupling, ambiguity is low given a clear problem/reproduction, and effort is 5 as moderate code and refactor/testing is needed.
---
# Plan

## Goal

Always persist audit trail metadata for every nono session, regardless of rollback, writable paths, or execution mode.

## Approach

Decouple audit session creation and metadata writing from rollback and tracked writable paths; always create a session directory and write session.json for every sandboxed execution, with rollback state/snapshots remaining conditional; introduce a global opt-out (e.g., --no-audit).

## Constraints
- No audit trail should be written if --no-audit is specified.
- Rollback-related artifacts (snapshots) remain conditional on writable tracked paths.
- Audit session directory and metadata must always be created unless opt-out is requested.
- Session metadata must always record sufficient data: command, start/end time, exit code, network events, etc.
- Minimal disruption to CLI interface; align with any other ongoing refactoring (e.g., #265).

## Subtasks

### task-1: Add --no-audit flag to CLI and propagate flag

Update CLI parsing to add a global --no-audit flag, document in help, and ensure the flag propagates to execution logic wherever a session is created.

**Acceptance criteria:**
- CLI help shows --no-audit global flag with correct description.
- --no-audit disables audit trail creation regardless of other options.
- Flag is available and respected in all sandbox execution code paths.

### task-2: Decouple audit metadata writing from rollback state

Refactor the main session logic in crates/nono-cli/src/main.rs to ensure that audit session directory and session.json are created and written for every execution, regardless of rollback or tracked_paths.

**Acceptance criteria:**
- session.json and audit session directory are always created unless --no-audit is passed.
- Audit trail for all executions (read-only, no-writable, allow-cwd, monitor, etc) is persisted by default.
- No duplicate or missing audit session directories.

### task-3: Refactor rollback artifact writing to remain path-conditional

Ensure that rollback artifact creation (snapshots, etc) stays conditional on presence of writable tracked paths, but does not block audit session creation.

**Acceptance criteria:**
- Rollback artifacts are created only when appropriate (writable user-specified tracked paths present).
- Audit trail is unaffected: always present unless --no-audit.
- No regression of rollback functionality.

### task-4: Update audit session metadata content

Ensure that audit sessions store all necessary metadata (command, start/end time, exit code, network activity, etc.) for every session, even if rollback state/snapshots are absent.

**Acceptance criteria:**
- session.json written in all audit session dirs has complete metadata.
- Metadata fields are not missing/None except those impossible for execution mode.
- End-to-end test shows expected audit information for runs with and without rollback.

### task-5: Update audit list to show all sessions

Update crates/nono-cli/src/audit_commands.rs (and helpers) so that audit list correctly displays all sessions regardless of execution mode, as long as audit trail is present.

**Acceptance criteria:**
- nono audit list shows all sessions created, including those without rollback.
- No 'No sessions found' for executions that occurred while audit enabled.
- Session display is accurate and not coupled to rollback artifacts.

### task-6: Comprehensively test audit trail coverage

Write/modify integration tests structured as a matrix: various combinations of (rollback on/off), (writable path present/absent), (allow-cwd), --no-audit flag, and confirm correct audit trail or its absence.

**Acceptance criteria:**
- Tests pass for all combinations, showing audit trail for everything except runs with --no-audit.
- At least one test for each scenario (read-only, monitor, with/without rollback, opt-out).
- Regression on #269 is fully covered by tests and cannot reoccur silently.


---

## Plan Review

*Reviewed by `plan-reviewer` at 2026-03-09 08:46:33 UTC*

**Verdict:** approve (confidence: high)

The plan is comprehensive, targets all the root causes, and decomposes the solution into clear, executable steps. Subtasks are well-scoped, and complexity/risk assessments are reasonable given the scope of decoupling core features. Suggestions are mostly for thoroughness, edge cases, and documentation. Safe to proceed to implementation.

### Concerns
- Possible tight coupling still exists between audit trail and rollback code paths; must validate after refactor.
- The plan assumes --no-audit is sufficient for privacy/opt-out, but does not mention config file opt-out or programmatic usage—future extension may be desired.
- Migration of existing sessions/audit entries if data model changes is not specifically addressed (not likely an issue, but should check).

### Suggestions
- Explicitly validate that audit and rollback are functionally independent post-refactor (separate tests/code review callout).
- Consider whether a config file or environment variable should also support opting out of audit for full coverage.
- Add a test that confirms running with only --no-audit leaves no trace, for privacy compliance.
- Ensure documentation/user-facing guidance is updated to clarify the new behavior, especially for users expecting audit trail only with rollback.
