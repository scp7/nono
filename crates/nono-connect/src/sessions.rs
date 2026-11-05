//! Console session listing (`GET /api/v1/sessions`).

use std::time::Duration;

use url::Url;

use crate::credential::BearerToken;
use crate::error::{ConnectError, Result};
use crate::protocol::{ListSessionsResponse, RemoteSession};
use crate::urls::console_endpoint;

const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;

fn http_agent() -> ureq::Agent {
    let tls_config = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .tls_config(tls_config)
        // Never follow a redirect with the bearer token attached: the console
        // origin was validated, a redirect target was not.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent()
}

/// Fetch every session the token's human can see.
pub fn fetch_sessions(console: &Url, token: &BearerToken) -> Result<Vec<RemoteSession>> {
    let endpoint = console_endpoint(console, "/api/v1/sessions");
    let authorization = token.authorization();
    let mut response = http_agent()
        .get(endpoint.as_str())
        .header("Authorization", authorization.as_str())
        .call()
        .map_err(|error| ConnectError::Transport(format!("console request failed: {error}")))?;
    drop(authorization);
    let status = response.status();
    if !status.is_success() {
        let hint = if status.as_u16() == 401 || status.as_u16() == 403 {
            " (check that the console token is valid and unexpired)"
        } else {
            ""
        };
        return Err(ConnectError::Transport(format!(
            "console returned HTTP {} while listing sessions{hint}",
            status.as_u16()
        )));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| ConnectError::Protocol(format!("invalid session response: {error}")))?;
    let parsed: ListSessionsResponse = serde_json::from_str(&body)
        .map_err(|error| ConnectError::Protocol(format!("invalid session response: {error}")))?;
    Ok(parsed.sessions)
}
