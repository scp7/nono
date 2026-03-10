---
complexity:
  scope: M
  risk: Med
  ambiguity: Low
  effort: 8
  rationale: The task involves coordinated changes across three crates (`nono`, `nono-cli`, `nono-proxy`), modification of core security sandboxing rules, and introduction of concurrent logic (running the proxy), which carries moderate risk and effort.
---
# Plan

## Goal

Integrate a network filtering proxy into the `nono` CLI to allow granular control over internet access for sandboxed applications, including content-type blocking.

## Approach

Introduce a `--network-policy` flag to the `nono run` command which specifies a JSON policy file. When used, `nono-cli` will start an instance of `nono-proxy` on localhost, configure the sandbox to only permit network access to this proxy, and set the standard proxy environment variables for the child process. The `nono-proxy` will be enhanced to filter traffic based on rules in the policy file, such as allowed domains and blocked content types.

## Constraints
- The solution must work within the existing `landlock` (Linux) and `seatbelt` (macOS) sandboxing frameworks.
- The network policy configuration should be defined in a simple, user-friendly JSON file.
- Initial implementation will focus on HTTP/HTTPS traffic.
- Content filtering will be based on response headers (e.g., `Content-Type`), not body inspection.

## Subtasks

### task-1: Define and Implement Network Policy Schema

Define a JSON schema for the network policy file. The schema should support an array of rules, including `allow_domains` (with wildcard support) and `block_content_types` (e.g., `"image/*"`, `"application/javascript"`). Update `crates/nono-cli/src/network_policy.rs` to parse this new structure. Create a sample `example-network-policy.json` file.

**Acceptance criteria:**
- A struct representing the network policy is defined and can be deserialized from JSON.
- The struct supports a list of allowed domain patterns.
- The struct supports a list of blocked content-type patterns.
- An `example-network-policy.json` file is added to `crates/nono-cli/data/`.
- Unit tests in `network_policy.rs` successfully parse valid policy files.

### task-2: Enhance `nono-proxy` to Filter by Content-Type

Update `nono-proxy` to perform filtering based on the network policy. Modify `crates/nono-proxy/src/config.rs` to accept the new policy structure. In `crates/nono-proxy/src/filter.rs`, implement logic to inspect the `Content-Type` header of proxied responses. If the content type matches a `block_content_types` rule, the proxy should return an HTTP 403 Forbidden response instead of the original content.

**Acceptance criteria:**
- The proxy server can be configured with the new network policy.
- When a response's `Content-Type` matches a blocked pattern, the proxy returns a 403 status code.
- When a response's `Content-Type` does not match a blocked pattern, the proxy forwards the response correctly.
- Requests to domains not on the `allow_domains` list are blocked with a 403 status code.
- Unit tests in `nono-proxy` verify this filtering behavior.

### task-3: Add `--network-policy` Flag to `nono-cli`

In `crates/nono-cli/src/cli.rs`, add a new optional argument `--network-policy <PATH>` to the `run` subcommand using `clap`. This argument will specify the path to the network policy JSON file.

**Acceptance criteria:**
- `nono run --help` shows the new `--network-policy` flag.
- The CLI application correctly parses the path provided to the flag.
- If the file at the given path does not exist, the CLI exits with an informative error.

### task-4: Integrate Proxy Lifecycle into `nono-cli`

Modify the execution strategy in `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` (and equivalents for other platforms if necessary). If the `--network-policy` flag is present: 1. Parse the policy file. 2. Find a free TCP port on `127.0.0.1`. 3. Start the `nono-proxy` server in a background Tokio task, configured with the parsed policy and listening on the selected port. 4. Store the proxy address for the sandboxing step.

**Acceptance criteria:**
- When `nono run` is invoked with the flag, the proxy starts successfully before the child process is executed.
- The proxy server is shut down gracefully when the child process exits.
- The CLI correctly handles errors during proxy startup (e.g., unable to bind to a port).

### task-5: Configure Sandbox to Enforce Proxy Usage

Update the sandbox configuration logic. 1. In `crates/nono/src/query.rs` and `src/sandbox/linux.rs`, add capabilities to restrict all network egress except for TCP connections to the specific `localhost` port the proxy is running on. 2. In `nono-cli`, when the proxy is active, configure the sandbox with this new network restriction. 3. Inject the `http_proxy`, `https_proxy`, `HTTP_PROXY`, and `HTTPS_PROXY` environment variables into the sandboxed process, pointing to `http://127.0.0.1:<port>`.

**Acceptance criteria:**
- The sandboxed process can only make network connections to the proxy's address and port.
- Direct requests to external sites (e.g., `curl google.com`) from within the sandbox fail with a permission denied error.
- The standard proxy environment variables are correctly set in the child process.
- The sandbox configuration remains unchanged if the `--network-policy` flag is not used.

### task-6: Add Integration Test for Network Filtering

Create a new integration test file `crates/nono-cli/tests/network_proxy.rs`. The test should use `nono run --network-policy` to execute a command like `curl` or `wget`. The test cases should verify: 1. Access to an allowed domain succeeds. 2. Access to a disallowed domain fails. 3. Downloading a resource with a blocked `Content-Type` (like an image) fails or returns an empty/error response. 4. Downloading an allowed resource succeeds.

**Acceptance criteria:**
- A test case confirms that `curl` can access an allowed URL through the proxy.
- A test case confirms that `curl` cannot access a disallowed URL.
- A test case confirms that attempting to download a `.js` or `.png` file (when blocked by policy) results in a non-200 status code.
- `cargo test -p nono-cli` passes.

### task-7: Create Documentation and Examples

Create a new documentation file `docs/network-filtering.md`. This document should explain the feature, detail the network policy JSON schema, and provide a complete, practical example that solves the user's original request: blocking JavaScript and images when browsing a webpage. Update the main `README.md` to link to this new guide.

**Acceptance criteria:**
- The `network-filtering.md` file exists and is well-written.
- The documentation clearly explains the policy file format with examples.
- A step-by-step guide demonstrates how to block specific content types.
- The `README.md` contains a link to the new documentation in a relevant section.


---

## Plan Review

*Reviewed by `plan-reviewer` at 2026-03-10 07:36:47 UTC*

**Verdict:** flag (confidence: high)

The plan is well-structured and decomposed, and demonstrates good coverage of user requirements for integrating a network-filtering proxy into nono. However, there are material gaps and architectural risks—most notably, the inability to filter Content-Type on encrypted HTTPS traffic without major additional work (transparent MITM), which is not addressed. There are also unaddressed edge cases in sandbox egress control, process isolation, error handling, and test reliability. These omissions need to be clarified and resolved before implementation, as they may undermine user expectations or security guarantees.

### Concerns
- Plan does not address HTTPS interception, so Content-Type filtering is likely impossible for most modern web traffic where responses are encrypted unless the proxy handles transparent MITM (which is nontrivial and has security risks).
- Blocking by Content-Type based only on headers (without body inspection) may not be sufficient for real granular filtering, as sometimes headers can be misleading or absent.
- No mention of error handling or logging strategy for audited network actions, failed connections, or denied resources—important for security transparency.
- Plan assumes that landlock (Linux) and seatbelt (macOS) can restrict egress to a fine-grained level (single port) for non-root users; this may not be fully portable or feasible on all supported OS versions.
- Integration/test subtask assumes availability of external resources (domains/URLs) for tests; this could cause flakiness or policy changes outside project control.
- No consideration for process termination edge cases (e.g., if the proxy crashes, how does the sandboxed app behave? Is egress still blocked?)
- Does not explicitly consider privilege separation or how to prevent a compromised child process from disabling the proxy locally.
- Ambiguity: not clear how the system handles non-HTTP(S) outbound traffic (e.g., DNS, other protocols).
- Complexity: The risk score is correct, but implementation effort may be underestimated given proxy lifecycle, security, cross-OS sandbox config, and robust test coverage.

### Suggestions
- Clearly state in documentation that HTTPS interception is not currently supported (or, if attempted, specify safe CA and opt-in mechanisms).
- Enhance design to clarify behavior for non-HTTP(S) traffic, and make limitations explicit.
- Include error logging and audit trail requirements in the proxy and CLI for denied or filtered connections.
- Add a plan for robustly handling proxy crashes—e.g., ensure the sandbox prevents all egress if the proxy becomes unavailable.
- Use local mock HTTP(S) servers and static test data for integration tests to avoid external flakiness.
- Document supported and unsupported OS versions and their sandbox limitations (especially related to network egress restriction granularity).
- Design for privilege separation between proxy and sandboxed app if possible.
- Ensure proper cleanup and teardown in CLI/proxy for all edge cases where things fail early, crash, or exit unexpectedly.
- Review/test pattern matching on Content-Type headers (some headers include parameters, wildcards).
