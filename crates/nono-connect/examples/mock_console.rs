//! Loopback mock of nono-console for manual testing of `nono-connect`.
//!
//! `cargo run -p nono-connect --example mock_console -- 127.0.0.1:8765`
//! then, with `NONO_CONNECT_TOKEN=test-token`:
//! `nono-connect --console http://127.0.0.1:8765 ps` and `nono-connect --console http://127.0.0.1:8765 demo`.
//!
//! The terminal echoes input back as `echo: ...`; typing `exit` ends the
//! session with status 3. Development only: plain HTTP/WS on loopback.

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Message;

const TOKEN: &str = "Bearer test-token";
const SESSIONS: &str = r#"{"sessions":[
 {"global_session_id":"local:mock:0001","backend_status":"ready",
  "record":{"name":"demo","status":"running","command":["bash"]},
  "agent":{"name":"Mock Agent"},"repo":null},
 {"global_session_id":"local:mock:0002","backend_status":"stopped",
  "record":{"name":"old","status":"exited","command":["claude"]},"agent":null,"repo":null}
]}"#;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8765".to_string());
    let listener = TcpListener::bind(&address).await?;
    eprintln!("mock console on http://{address}");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = serve(stream).await {
                eprintln!("connection error: {error}");
            }
        });
    }
}

async fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    let mut head = [0u8; 1024];
    let peeked = stream.peek(&mut head).await?;
    let head = String::from_utf8_lossy(&head[..peeked]);
    if head.starts_with("GET /api/v1/sessions ") || head.starts_with("GET /api/v1/sessions\r") {
        let authorized = head.lines().any(|line| {
            line == format!("authorization: {TOKEN}") || line == format!("Authorization: {TOKEN}")
        });
        let (status, body) = if authorized {
            ("200 OK", SESSIONS)
        } else {
            ("401 Unauthorized", "{}")
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        return stream.shutdown().await;
    }

    let callback = |request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
        let auth_ok = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            == Some(TOKEN);
        let proto_ok = request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            == Some("nono.terminal.v1");
        if !auth_ok || !proto_ok {
            let mut error = ErrorResponse::new(None);
            *error.status_mut() = StatusCode::UNAUTHORIZED;
            return Err(error);
        }
        eprintln!("attach {}", request.uri());
        response.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static("nono.terminal.v1"),
        );
        Ok(response)
    };
    let mut socket = tokio_tungstenite::accept_hdr_async(stream, callback)
        .await
        .map_err(std::io::Error::other)?;
    let attached = r#"{"type":"attached","protocol_version":"1","cols":80,"rows":24}"#;
    socket
        .send(Message::Text(attached.into()))
        .await
        .map_err(std::io::Error::other)?;
    socket
        .send(Message::Binary(
            b"welcome to the mock session \xe2\x82".to_vec().into(),
        ))
        .await
        .map_err(std::io::Error::other)?;
    socket
        .send(Message::Binary(b"\xac\r\n".to_vec().into()))
        .await
        .map_err(std::io::Error::other)?;
    let mut line = Vec::new();
    while let Some(message) = socket.next().await {
        match message.map_err(std::io::Error::other)? {
            Message::Binary(bytes) => {
                line.extend_from_slice(&bytes);
                let echo = [b"echo: ".as_slice(), &bytes, b"\r\n"].concat();
                socket
                    .send(Message::Binary(echo.into()))
                    .await
                    .map_err(std::io::Error::other)?;
                if line.windows(4).any(|w| w == b"exit") {
                    let exited = r#"{"type":"session_exited","exit_code":3}"#;
                    socket
                        .send(Message::Text(exited.into()))
                        .await
                        .map_err(std::io::Error::other)?;
                    break;
                }
            }
            Message::Text(text) => {
                eprintln!("control {text}");
                if text.contains("\"detach\"") {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    let _ = socket.close(None).await;
    Ok(())
}
