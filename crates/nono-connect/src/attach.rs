//! The terminal attach loop (remote-attach-v1 frames over WSS).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, header};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use crate::credential::BearerToken;
use crate::detach::DetachMatcher;
use crate::error::{ConnectError, Result};
use crate::protocol::{
    PROTOCOL_VERSION_V1, ServerControl, TERMINAL_PROTOCOL_V1, detach_message, parse_server_control,
    resize_message,
};
use crate::sanitize::sanitize_for_terminal;
use crate::terminal::{self, ResizeWatcher, TerminalSession};
use crate::urls::{set_initial_terminal_size, validate_transport_url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest single frame accepted from the console.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// How an attachment ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachOutcome {
    /// The local user detached; the hosted session keeps running.
    Detached,
    /// The hosted session ended with this (non-negative) exit status.
    SessionExited(i32),
}

/// Attach the local terminal to the session at `url`.
///
/// `url` must already be origin-checked by the caller. `on_connected` runs
/// once the WebSocket is open, before the terminal enters raw mode.
pub async fn attach(
    mut url: Url,
    token: &BearerToken,
    detach_sequence: Vec<u8>,
    on_connected: impl FnOnce(&Url),
) -> Result<AttachOutcome> {
    validate_transport_url(&url)?;
    let initial = terminal::size();
    set_initial_terminal_size(&mut url, initial.0, initial.1);

    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| ConnectError::Config(format!("invalid terminal request: {error}")))?;
    let authorization = token.authorization();
    let mut auth_value = HeaderValue::from_str(authorization.as_str())
        .map_err(|_| ConnectError::Config("invalid connect token".to_string()))?;
    drop(authorization);
    auth_value.set_sensitive(true);
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, auth_value);
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(TERMINAL_PROTOCOL_V1),
    );

    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    let (socket, response) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(config),
            false,
            Some(tls_connector()?),
        ),
    )
    .await
    .map_err(|_| ConnectError::Transport("terminal connection timed out".to_string()))?
    .map_err(|error| ConnectError::Transport(format!("terminal connection failed: {error}")))?;

    let negotiated = response
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok());
    if negotiated != Some(TERMINAL_PROTOCOL_V1) {
        return Err(ConnectError::Protocol(format!(
            "console did not negotiate the required {TERMINAL_PROTOCOL_V1} protocol"
        )));
    }
    on_connected(&url);

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut matcher = DetachMatcher::new(detach_sequence);
    let mut resize = ResizeWatcher::new(initial)?;
    let mut session = TerminalSession::start()?;
    ws_tx
        .send(Message::Text(resize_message(initial.0, initial.1).into()))
        .await
        .map_err(ws_error)?;

    let outcome = loop {
        tokio::select! {
            chunk = session.read() => {
                let bytes = match chunk {
                    Some(Ok(bytes)) if !bytes.is_empty() => bytes,
                    Some(Err(error)) => break Err(ConnectError::Io(error)),
                    // End of local input: detach rather than leave a dead writer.
                    _ => break send_detach(&mut ws_tx).await.map(|()| AttachOutcome::Detached),
                };
                let matched = matcher.push(&bytes);
                if !matched.forward.is_empty()
                    && let Err(error) = ws_tx.send(Message::Binary(matched.forward.into())).await
                {
                    break Err(ws_error(error));
                }
                if matched.detach {
                    break send_detach(&mut ws_tx).await.map(|()| AttachOutcome::Detached);
                }
            }
            (cols, rows) = resize.changed() => {
                if let Err(error) = ws_tx.send(Message::Text(resize_message(cols, rows).into())).await {
                    break Err(ws_error(error));
                }
            }
            message = ws_rx.next() => match message {
                Some(Ok(Message::Binary(bytes))) => {
                    if let Err(error) = session.write(bytes.to_vec()).await {
                        break Err(error);
                    }
                }
                Some(Ok(Message::Text(text))) => match handle_control(text.as_str()) {
                    Ok(None) => {}
                    Ok(Some(outcome)) => break Ok(outcome),
                    Err(error) => break Err(error),
                },
                Some(Ok(Message::Ping(payload))) => {
                    if let Err(error) = ws_tx.send(Message::Pong(payload)).await {
                        break Err(ws_error(error));
                    }
                }
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    break Err(ConnectError::Protocol(
                        "terminal connection closed without a session-ended event".to_string(),
                    ));
                }
                Some(Err(error)) => break Err(ws_error(error)),
            }
        }
    };
    // Flush output and restore the terminal before the caller prints anything.
    drop(session);
    let _ = ws_tx.close().await;
    outcome
}

/// Interpret one server control frame. `Some` ends the attachment.
fn handle_control(text: &str) -> Result<Option<AttachOutcome>> {
    match parse_server_control(text)? {
        ServerControl::Attached {
            protocol_version, ..
        } => {
            if protocol_version != PROTOCOL_VERSION_V1 {
                return Err(ConnectError::Protocol(format!(
                    "console selected unsupported terminal protocol {}",
                    sanitize_for_terminal(&protocol_version)
                )));
            }
            Ok(None)
        }
        ServerControl::SessionExited {
            exit_code: Some(code),
        } if code >= 0 => Ok(Some(AttachOutcome::SessionExited(code))),
        ServerControl::SessionExited { exit_code: Some(_) } => Err(ConnectError::Protocol(
            "remote session returned an invalid negative exit status".to_string(),
        )),
        ServerControl::SessionExited { exit_code: None } => Err(ConnectError::Protocol(
            "remote session ended without an exit status".to_string(),
        )),
        ServerControl::Error { code, message } => {
            let prefix = code
                .map(|value| format!("{}: ", sanitize_for_terminal(&value)))
                .unwrap_or_default();
            Err(ConnectError::Protocol(format!(
                "{prefix}{}",
                sanitize_for_terminal(&message)
            )))
        }
    }
}

async fn send_detach<S>(sink: &mut S) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    sink.send(Message::Text(detach_message().into()))
        .await
        .map_err(ws_error)
}

fn ws_error(error: tokio_tungstenite::tungstenite::Error) -> ConnectError {
    ConnectError::Transport(format!("terminal connection failed: {error}"))
}

/// rustls with the `ring` provider named explicitly and the platform's native
/// trust anchors (the Windows certificate store on Windows, so enterprise
/// roots deployed by policy are honored). An empty store is an error, never
/// an unverified connection.
fn tls_connector() -> Result<tokio_tungstenite::Connector> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err(ConnectError::Transport(
            "no trusted root certificates found for the terminal connection".to_string(),
        ));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| ConnectError::Transport(format!("terminal TLS configuration: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_map_to_outcomes() {
        assert!(matches!(
            handle_control(r#"{"type":"attached","protocol_version":"1","cols":1,"rows":1}"#),
            Ok(None)
        ));
        assert!(
            handle_control(r#"{"type":"attached","protocol_version":"2","cols":1,"rows":1}"#)
                .is_err()
        );
        assert!(matches!(
            handle_control(r#"{"type":"session_exited","exit_code":3}"#),
            Ok(Some(AttachOutcome::SessionExited(3)))
        ));
        assert!(handle_control(r#"{"type":"session_exited","exit_code":-1}"#).is_err());
        assert!(handle_control(r#"{"type":"session_exited","exit_code":null}"#).is_err());
    }

    #[test]
    fn console_error_messages_are_sanitized() {
        let Err(error) = handle_control(
            r#"{"type":"error","code":"busy","message":"x\u001b]52;c;AA==\u0007y"}"#,
        ) else {
            panic!("error frame must fail the attachment");
        };
        assert_eq!(error.to_string(), "busy: xy");
    }
}
