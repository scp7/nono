//! remote-attach-v1 wire types (`docs/protocols/remote-attach-v1.md`).

use serde::{Deserialize, Serialize};

use crate::error::{ConnectError, Result};
use crate::sanitize::sanitize_for_terminal;

/// WebSocket subprotocol the client offers and requires.
pub const TERMINAL_PROTOCOL_V1: &str = "nono.terminal.v1";
/// `protocol_version` carried by every client control message.
pub const PROTOCOL_VERSION_V1: &str = "1";

/// `GET /api/v1/sessions` response.
#[derive(Debug, Deserialize)]
pub struct ListSessionsResponse {
    /// Sessions visible to the authenticated human.
    pub sessions: Vec<RemoteSession>,
}

/// One hosted session. Every string here is console-controlled and must be
/// sanitized before it reaches the terminal.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteSession {
    /// Globally unique session ID.
    pub global_session_id: String,
    /// Backend status; `ready` when attachable.
    pub backend_status: String,
    /// Runtime record.
    pub record: Option<RemoteSessionRecord>,
    /// Agent metadata.
    pub agent: Option<RemoteAgent>,
    /// Repository metadata.
    pub repo: Option<RemoteRepo>,
}

/// Runtime record of a hosted session.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteSessionRecord {
    /// Human-friendly name.
    pub name: Option<String>,
    /// Runtime status; `running` when live.
    pub status: String,
    /// Command line of the hosted process.
    #[serde(default)]
    pub command: Vec<String>,
}

/// Agent metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteAgent {
    /// Agent display name.
    pub name: String,
}

/// Repository metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteRepo {
    /// `owner/name`.
    pub full_name: String,
    /// Base branch.
    pub base_branch: String,
}

impl RemoteSession {
    /// Live: backend ready and runtime running.
    pub fn is_live(&self) -> bool {
        self.backend_status == "ready"
            && self
                .record
                .as_ref()
                .is_some_and(|record| record.status == "running")
    }

    /// The recorded name, or the global ID when there is none.
    pub fn display_name(&self) -> &str {
        self.record
            .as_ref()
            .and_then(|record| record.name.as_deref())
            .unwrap_or(&self.global_session_id)
    }

    /// Runtime status when the backend is ready, else the backend status.
    pub fn status(&self) -> &str {
        if self.backend_status == "ready" {
            self.record
                .as_ref()
                .map(|record| record.status.as_str())
                .unwrap_or(&self.backend_status)
        } else {
            &self.backend_status
        }
    }

    /// Agent name, or a bare program name; paths are runtime plumbing.
    pub fn agent(&self) -> &str {
        self.agent
            .as_ref()
            .map(|agent| agent.name.as_str())
            .or_else(|| {
                self.record
                    .as_ref()
                    .and_then(|record| record.command.first().map(String::as_str))
                    .filter(|program| {
                        !program.is_empty() && !program.contains('/') && !program.contains('\\')
                    })
            })
            .unwrap_or("-")
    }

    /// `owner/name#branch`, or `-`.
    pub fn repo(&self) -> String {
        self.repo
            .as_ref()
            .map(|repo| format!("{}#{}", repo.full_name, repo.base_branch))
            .unwrap_or_else(|| "-".to_string())
    }
}

/// Keep live sessions unless `all`, sorted by name then ID.
pub fn filter_sessions(mut sessions: Vec<RemoteSession>, all: bool) -> Vec<RemoteSession> {
    if !all {
        sessions.retain(RemoteSession::is_live);
    }
    sessions.sort_by(|left, right| {
        left.display_name()
            .cmp(right.display_name())
            .then_with(|| left.global_session_id.cmp(&right.global_session_id))
    });
    sessions
}

/// Select one session by exact global ID, exact name, or unambiguous ID prefix.
pub fn select_named_session(sessions: &[RemoteSession], target: &str) -> Result<RemoteSession> {
    if target.is_empty() {
        return Err(ConnectError::Config(
            "remote session selector is empty".to_string(),
        ));
    }
    let exact = sessions
        .iter()
        .filter(|session| {
            session.global_session_id == target
                || session.record.as_ref().and_then(|r| r.name.as_deref()) == Some(target)
        })
        .collect::<Vec<_>>();
    let candidates = if exact.is_empty() {
        sessions
            .iter()
            .filter(|session| session.global_session_id.starts_with(target))
            .collect::<Vec<_>>()
    } else {
        exact
    };
    match candidates.as_slice() {
        [session] => Ok((*session).clone()),
        [] => Err(ConnectError::SessionNotFound(target.to_string())),
        _ => Err(ConnectError::Config(format!(
            "remote session selector '{target}' is ambiguous"
        ))),
    }
}

/// Server-to-client control frames.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerControl {
    /// The backend attachment is ready.
    Attached {
        /// Must be `"1"`.
        protocol_version: String,
        /// Applied columns.
        cols: u16,
        /// Applied rows.
        rows: u16,
    },
    /// The hosted session ended.
    SessionExited {
        /// Hosted process status; `None` when genuinely unknown.
        exit_code: Option<i32>,
    },
    /// Fatal attach error.
    Error {
        /// Machine-readable code.
        code: Option<String>,
        /// Human-readable message (console-controlled; sanitize).
        message: String,
    },
}

/// Parse a server control frame.
///
/// serde's messages quote console-supplied text (for example an unknown
/// `type`), so the error is sanitized before it can reach the terminal.
pub fn parse_server_control(text: &str) -> Result<ServerControl> {
    serde_json::from_str(text).map_err(|error| {
        ConnectError::Protocol(format!(
            "invalid terminal control frame: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })
}

/// The `resize` control message. Zero dimensions are clamped to one, since
/// the protocol requires non-zero values.
pub fn resize_message(cols: u16, rows: u16) -> String {
    serde_json::json!({
        "type": "resize",
        "protocol_version": PROTOCOL_VERSION_V1,
        "cols": cols.max(1),
        "rows": rows.max(1),
    })
    .to_string()
}

/// The `detach` control message.
pub fn detach_message() -> String {
    serde_json::json!({ "type": "detach", "protocol_version": PROTOCOL_VERSION_V1 }).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn session(id: &str, name: Option<&str>, backend: &str, status: &str) -> RemoteSession {
        RemoteSession {
            global_session_id: id.to_string(),
            backend_status: backend.to_string(),
            record: Some(RemoteSessionRecord {
                name: name.map(str::to_string),
                status: status.to_string(),
                command: vec!["claude".to_string()],
            }),
            agent: None,
            repo: None,
        }
    }

    #[test]
    fn filter_keeps_live_sessions_sorted() {
        let sessions = vec![
            session("c", Some("zeta"), "ready", "running"),
            session("a", Some("alpha"), "ready", "running"),
            session("b", Some("beta"), "starting", "running"),
            session("d", Some("delta"), "ready", "exited"),
        ];
        let live = filter_sessions(sessions.clone(), false);
        let names: Vec<_> = live.iter().map(RemoteSession::display_name).collect();
        assert_eq!(names, ["alpha", "zeta"]);
        assert_eq!(filter_sessions(sessions, true).len(), 4);
    }

    #[test]
    fn selection_prefers_exact_matches_and_refuses_ambiguity() {
        let sessions = vec![
            session("abc-1", Some("abc"), "ready", "running"),
            session("abc-2", Some("other"), "ready", "running"),
        ];
        assert_eq!(
            select_named_session(&sessions, "abc")
                .unwrap()
                .global_session_id,
            "abc-1"
        );
        assert_eq!(
            select_named_session(&sessions, "abc-2")
                .unwrap()
                .global_session_id,
            "abc-2"
        );
        assert!(select_named_session(&sessions, "ab").is_err());
        assert!(select_named_session(&sessions, "").is_err());
        assert!(matches!(
            select_named_session(&sessions, "zzz"),
            Err(ConnectError::SessionNotFound(_))
        ));
    }

    #[test]
    fn control_frames_parse_and_unknown_types_fail() {
        assert!(matches!(
            parse_server_control(r#"{"type":"session_exited","exit_code":2}"#).unwrap(),
            ServerControl::SessionExited { exit_code: Some(2) }
        ));
        assert!(matches!(
            parse_server_control(
                r#"{"type":"attached","protocol_version":"1","cols":80,"rows":24}"#
            )
            .unwrap(),
            ServerControl::Attached { .. }
        ));
        assert!(parse_server_control(r#"{"type":"grant_admin"}"#).is_err());
        assert!(parse_server_control("not json").is_err());
        let Err(error) = parse_server_control(r#"{"type":"a\u001b]52;c;QQ==\u0007b"}"#) else {
            panic!("unknown control type must fail");
        };
        assert!(!error.to_string().contains('\u{1b}'));
        assert!(!error.to_string().contains('\u{7}'));
    }

    #[test]
    fn resize_never_sends_zero() {
        let value: serde_json::Value = serde_json::from_str(&resize_message(0, 0)).unwrap();
        assert_eq!(value["cols"], 1);
        assert_eq!(value["rows"], 1);
        assert_eq!(value["protocol_version"], "1");
    }
}
