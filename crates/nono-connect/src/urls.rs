//! URL policy for console and terminal endpoints (remote-attach-v1).
//!
//! Everything here decides where a bearer token is sent, so it fails closed:
//! HTTPS/WSS only off loopback, no URL credentials, queries or fragments, and
//! origin comparison by parsed host and effective port, never by string prefix.

use url::{Host, Url};

use crate::error::{ConnectError, Result};

/// Validate a console origin given by the operator.
pub fn validate_console_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .map_err(|error| ConnectError::Config(format!("invalid console URL: {error}")))?;
    if url.cannot_be_a_base() || !matches!(url.scheme(), "http" | "https") {
        return Err(ConnectError::Config(
            "console URL must use http:// or https://".to_string(),
        ));
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(ConnectError::Config(
            "console URL must use HTTPS; HTTP is allowed only for loopback development".to_string(),
        ));
    }
    if has_url_secrets_or_query(&url) {
        return Err(ConnectError::Config(
            "console URL must not contain credentials, query parameters, or fragments".to_string(),
        ));
    }
    Ok(url)
}

/// Refuse cleartext WebSockets except on loopback.
pub fn validate_transport_url(url: &Url) -> Result<()> {
    if url.scheme() == "wss" || (url.scheme() == "ws" && is_loopback(url)) {
        Ok(())
    } else {
        Err(ConnectError::Config(
            "remote attach must use WSS; WS is allowed only for loopback development".to_string(),
        ))
    }
}

/// Shape check for a `ws(s)://` URL typed by the operator.
pub fn validate_direct_attach_url(url: &Url) -> Result<()> {
    if has_url_secrets_or_query(url) {
        return Err(ConnectError::Config(
            "attach URLs must not contain credentials, query parameters, or fragments".to_string(),
        ));
    }
    Ok(())
}

/// Whether `url` names the same host and effective port as `origin`.
///
/// Scheme is deliberately not compared: the console is `https://` while the
/// terminal URL it issues is `wss://` on the same host.
pub fn same_origin_host_port(url: &Url, origin: &Url) -> bool {
    match (url.host_str(), origin.host_str()) {
        (Some(host), Some(candidate)) => {
            candidate.eq_ignore_ascii_case(host)
                && url.port_or_known_default() == origin.port_or_known_default()
        }
        _ => false,
    }
}

/// Refuse to send the console token to an origin the operator did not name.
///
/// This client has no enrollment state to discover a console from, so a
/// direct `wss://` target is accepted only when it matches `--console`.
/// Loopback stays the documented development exception.
pub fn verify_attach_origin(url: &Url, console: Option<&Url>) -> Result<()> {
    if is_loopback(url) {
        return Ok(());
    }
    if console.is_some_and(|origin| same_origin_host_port(url, origin)) {
        return Ok(());
    }
    Err(ConnectError::ActionRequired(format!(
        "refusing to send console credentials to '{}': pass --console naming the console that \
         issued this session",
        url.host_str().unwrap_or("<no host>")
    )))
}

/// Loopback by parsed host: `localhost`, `127.0.0.0/8`, or `::1`.
pub fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// `path` appended to the console URL, preserving any path prefix.
pub fn console_endpoint(console: &Url, path: &str) -> Url {
    let mut url = console.clone();
    let joined = format!(
        "{}/{}",
        url.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    url.set_path(&joined);
    url
}

/// The terminal WebSocket URL for a session on `console`.
pub fn terminal_url(console: &Url, session_id: &str) -> Result<Url> {
    let path = format!(
        "/api/v1/sessions/{}/terminal",
        urlencoding::encode(session_id)
    );
    let mut url = console_endpoint(console, &path);
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| ConnectError::Config("could not construct terminal URL".to_string()))?;
    Ok(url)
}

/// Append the initial terminal dimensions the server applies before replay.
pub fn set_initial_terminal_size(url: &mut Url, cols: u16, rows: u16) {
    url.query_pairs_mut()
        .append_pair("cols", &cols.to_string())
        .append_pair("rows", &rows.to_string());
}

fn has_url_secrets_or_query(url: &Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    #[test]
    fn console_urls_require_https_off_loopback() {
        assert!(validate_console_url("https://console.example").is_ok());
        assert!(validate_console_url("http://console.example").is_err());
        assert!(validate_console_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_console_url("http://[::1]:8080").is_ok());
        assert!(validate_console_url("http://localhost:8080").is_ok());
        assert!(validate_console_url("ftp://console.example").is_err());
        assert!(validate_console_url("https://console.example?token=x").is_err());
        assert!(validate_console_url("https://user@console.example").is_err());
        assert!(validate_console_url("https://console.example/#frag").is_err());
    }

    #[test]
    fn loopback_is_decided_by_parsed_host_not_prefix() {
        assert!(!is_loopback(&url("http://localhost.evil.example")));
        assert!(!is_loopback(&url("http://127.0.0.1.evil.example")));
        assert!(is_loopback(&url("ws://127.0.0.1/terminal")));
    }

    #[test]
    fn transport_refuses_cleartext_off_loopback() {
        assert!(validate_transport_url(&url("wss://console.example/t")).is_ok());
        assert!(validate_transport_url(&url("ws://console.example/t")).is_err());
        assert!(validate_transport_url(&url("ws://localhost/t")).is_ok());
        assert!(validate_transport_url(&url("https://console.example/t")).is_err());
    }

    #[test]
    fn attach_origin_must_match_the_named_console() {
        let console = url("https://console.example");
        let target = url("wss://Console.Example/api/v1/sessions/a/terminal");
        assert!(verify_attach_origin(&target, Some(&console)).is_ok());
        assert!(verify_attach_origin(&target, None).is_err());
        for evil in [
            "wss://evil-console.example/t",
            "wss://console.example.evil.test/t",
            "wss://console.example:8443/t",
        ] {
            assert!(
                verify_attach_origin(&url(evil), Some(&console)).is_err(),
                "{evil}"
            );
        }
        assert!(verify_attach_origin(&url("ws://127.0.0.1:9/t"), None).is_ok());
    }

    #[test]
    fn terminal_url_preserves_prefix_and_encodes_the_id() {
        let terminal = terminal_url(&url("https://example.com/console/"), "local:h/x").unwrap();
        assert_eq!(
            terminal.as_str(),
            "wss://example.com/console/api/v1/sessions/local%3Ah%2Fx/terminal"
        );
        let mut sized = terminal;
        set_initial_terminal_size(&mut sized, 120, 40);
        assert_eq!(sized.query(), Some("cols=120&rows=40"));
    }

    #[test]
    fn direct_attach_urls_reject_secrets() {
        assert!(validate_direct_attach_url(&url("wss://c.example/t?token=s")).is_err());
        assert!(validate_direct_attach_url(&url("wss://u:p@c.example/t")).is_err());
        assert!(validate_direct_attach_url(&url("wss://c.example/t")).is_ok());
    }
}
