# Review

## Revision 0 — Verdict: needs_revision

*2026-03-10 07:44:29 UTC*

The implementation is incomplete and has significant architectural issues. While some of the boilerplate for the new CLI flag and policy parsing is in place, the core functionality of filtering network traffic is not integrated. The changes introduce a new, disconnected filtering module instead of enhancing the existing proxy, and key logic for starting the proxy and configuring the sandbox is missing.

### Actionable Feedback:

1.  **Core Integration Failure:** The new filtering logic in `crates/nono-proxy/src/filter.rs` is not connected to the actual proxy server. The existing proxy logic in `connect.rs` and `reverse.rs` remains unmodified and does not perform content-type filtering. You must integrate the new filtering capabilities into the existing proxy architecture, not create a separate, unused module.

2.  **Configuration Mismatch:** The CLI parses a `NetworkPolicy` struct, but the `nono-proxy` crate expects a `ProxyConfig` struct. The `ProxyConfig` struct itself was not updated to support `block_content_types`, and there is no logic to convert the CLI's policy into the proxy's configuration.

3.  **Incomplete Proxy Lifecycle:** In `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`, the logic to start the proxy is commented out. The implementation for gracefully shutting down the proxy when the child process exits is also missing.

4.  **Missing Sandbox Configuration:** The code to configure the sandbox to restrict network access to the proxy port (`NetworkMode::ProxyOnly`) and to inject the required `HTTP_PROXY`/`HTTPS_PROXY` environment variables into the child process is not implemented.

5.  **Security Flaw in Domain Matching:** The domain matching logic in the new `nono-proxy/src/filter.rs` (`host.ends_with(domain)`) is insecure. A rule for `"example.com"` would incorrectly allow a connection to `"evil-example.com"`. This is a regression from the more robust suffix/wildcard matching already present in `nono/src/net_filter.rs`.

6.  **Missing Integration Tests:** The required integration test file (`crates/nono-cli/tests/network_proxy.rs`) and its test cases are completely missing. These are critical for verifying the feature's correctness and security.

7.  **Incomplete Documentation:** The main `README.md` file was not updated to link to the new `docs/network-filtering.md` documentation as required by the spec.

To proceed, please focus on integrating the new functionality into the existing proxy architecture, complete the implementation of the proxy lifecycle and sandbox configuration, add the required tests, and address the security issue in the domain matching logic.

---
