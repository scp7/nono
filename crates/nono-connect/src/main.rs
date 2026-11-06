//! `nono-connect`: attach this terminal to a session hosted on the nono
//! platform. Experimental; see `docs/experimental/windows-remote-connect.md`.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use nono_connect::attach::{AttachOutcome, attach};
use nono_connect::credential::{self, BearerToken};
use nono_connect::detach::{DEFAULT_DETACH_SEQUENCE, format_detach_sequence};
use nono_connect::protocol::{RemoteSession, filter_sessions, select_named_session};
use nono_connect::sanitize::sanitize_for_terminal;
use nono_connect::sessions::fetch_sessions;
use nono_connect::urls::{
    terminal_url, validate_console_url, validate_direct_attach_url, verify_attach_origin,
};
use nono_connect::{ConnectError, Result, terminal};
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "nono-connect",
    version,
    about = "Attach this terminal to a session hosted on the nono platform (experimental)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    connect: ConnectArgs,
}

#[derive(clap::Args, Debug)]
struct ConnectArgs {
    /// Session name/global ID (or unambiguous ID prefix), or a complete wss:// terminal URL
    target: Option<String>,

    #[command(flatten)]
    console: ConsoleArgs,
}

#[derive(clap::Args, Debug)]
struct ConsoleArgs {
    /// nono-console origin, e.g. https://console.example.com
    #[arg(long, env = "NONO_CONSOLE_URL", global = true)]
    console: Option<String>,

    /// Read the console bearer token from a file (Unix only, mode 0600); defaults to NONO_CONNECT_TOKEN
    #[arg(long, env = "NONO_CONNECT_TOKEN_FILE", global = true)]
    token_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List sessions on the console
    Ps {
        /// Include inactive sessions
        #[arg(long)]
        all: bool,
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            // Errors can quote console-controlled text; never let it drive the terminal.
            eprintln!(
                "nono-connect: {}",
                sanitize_for_terminal(&error.to_string())
            );
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    // `nono-connect <target> ps` must not silently drop the target. A session
    // literally named like a subcommand can be selected by its global ID.
    if cli.command.is_some() && cli.connect.target.is_some() {
        return Err(ConnectError::Config(
            "a session target cannot be combined with a subcommand".to_string(),
        ));
    }
    match cli.command {
        Some(Command::Ps { all, json }) => run_ps(&cli.connect.console, all, json).map(|()| 0),
        None => run_connect(cli.connect),
    }
}

fn required_console(args: &ConsoleArgs) -> Result<Url> {
    let value = args.console.as_deref().ok_or_else(|| {
        ConnectError::ActionRequired(
            "pass --console or set NONO_CONSOLE_URL (console discovery is not available in this \
             experimental client yet)"
                .to_string(),
        )
    })?;
    validate_console_url(value)
}

fn run_ps(args: &ConsoleArgs, all: bool, json: bool) -> Result<()> {
    let console = required_console(args)?;
    let token = credential::load(args.token_file.as_deref())?;
    let sessions = filter_sessions(fetch_sessions(&console, &token)?, all);
    if json {
        let text = serde_json::to_string_pretty(&sessions)
            .map_err(|error| ConnectError::Config(format!("JSON serialization failed: {error}")))?;
        println!("{text}");
        return Ok(());
    }
    if sessions.is_empty() {
        eprintln!("No {}sessions found.", if all { "" } else { "live " });
        return Ok(());
    }
    print_sessions(&sessions);
    Ok(())
}

fn print_sessions(sessions: &[RemoteSession]) {
    println!(
        "{:>3}  {:<24} {:<10} {:<16} REPO",
        "#", "NAME", "STATUS", "AGENT"
    );
    for (index, session) in sessions.iter().enumerate() {
        println!(
            "{:>3}  {:<24} {:<10} {:<16} {}",
            index + 1,
            sanitize_for_terminal(session.display_name()),
            sanitize_for_terminal(session.status()),
            sanitize_for_terminal(session.agent()),
            sanitize_for_terminal(&session.repo()),
        );
    }
}

fn run_connect(args: ConnectArgs) -> Result<i32> {
    if !terminal::is_interactive() {
        return Err(ConnectError::ActionRequired(
            "nono-connect requires an interactive terminal".to_string(),
        ));
    }
    let token = credential::load(args.console.token_file.as_deref())?;
    let url = resolve_attach_url(args.target.as_deref(), &args.console, &token)?;
    let detach_sequence = DEFAULT_DETACH_SEQUENCE.to_vec();
    let detach_label = format_detach_sequence(&detach_sequence);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| ConnectError::Config(format!("could not start runtime: {error}")))?;
    eprintln!("Connecting…");
    let outcome = runtime.block_on(attach(url, &token, detach_sequence, |url| {
        let transport = if url.scheme() == "wss" {
            "WSS, TLS encrypted"
        } else {
            "WS, loopback only"
        };
        eprintln!(
            "Connected to {} ({transport}). Detach with {detach_label}.\r",
            url.host_str().unwrap_or("console")
        );
    }));
    drop(token);
    // The console input thread may be blocked in an uncancellable read; do not
    // wait for it.
    runtime.shutdown_background();
    match outcome? {
        AttachOutcome::Detached => {
            eprintln!("Detached from remote session.");
            Ok(0)
        }
        AttachOutcome::SessionExited(0) => Ok(0),
        AttachOutcome::SessionExited(code) => Ok(platform_exit_code(code)),
    }
}

/// Unix truncates exit statuses to 8 bits; keep a non-zero status non-zero.
fn platform_exit_code(code: i32) -> i32 {
    if cfg!(unix) { code.clamp(1, 255) } else { code }
}

fn resolve_attach_url(
    target: Option<&str>,
    args: &ConsoleArgs,
    token: &BearerToken,
) -> Result<Url> {
    let console = args
        .console
        .as_deref()
        .map(validate_console_url)
        .transpose()?;
    if let Some(target) = target
        && let Ok(url) = Url::parse(target)
        && matches!(url.scheme(), "ws" | "wss")
    {
        validate_direct_attach_url(&url)?;
        verify_attach_origin(&url, console.as_ref())?;
        return Ok(url);
    }
    let console = required_console(args)?;
    let sessions = filter_sessions(fetch_sessions(&console, token)?, false);
    let session = match target {
        Some(value) => select_named_session(&sessions, value)?,
        None => prompt_for_session(&sessions)?,
    };
    eprintln!(
        "Attaching to {}",
        sanitize_for_terminal(session.display_name())
    );
    terminal_url(&console, &session.global_session_id)
}

/// A line-based picker: portable, and it never puts the console in raw mode.
fn prompt_for_session(sessions: &[RemoteSession]) -> Result<RemoteSession> {
    match sessions {
        [] => Err(ConnectError::ActionRequired(
            "the console has no live sessions visible to this user".to_string(),
        )),
        [only] => Ok(only.clone()),
        _ => {
            print_sessions(sessions);
            let mut line = String::new();
            loop {
                eprint!("Select a session [1-{}] (q to cancel): ", sessions.len());
                io::stderr().flush()?;
                line.clear();
                if io::stdin().lock().read_line(&mut line)? == 0 {
                    return Err(ConnectError::ActionRequired(
                        "selection cancelled".to_string(),
                    ));
                }
                let answer = line.trim();
                if answer.eq_ignore_ascii_case("q") {
                    return Err(ConnectError::ActionRequired(
                        "selection cancelled".to_string(),
                    ));
                }
                if let Ok(choice) = answer.parse::<usize>()
                    && let Some(session) = choice.checked_sub(1).and_then(|i| sessions.get(i))
                {
                    return Ok(session.clone());
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_target_with_a_subcommand_is_refused() {
        for argv in [
            ["nono-connect", "demo", "ps"],
            ["nono-connect", "ps", "demo"],
        ] {
            if let Ok(cli) = Cli::try_parse_from(argv) {
                assert!(
                    matches!(run(cli), Err(ConnectError::Config(_))),
                    "{argv:?} must be refused"
                );
            }
        }
    }

    #[test]
    fn platform_exit_codes_stay_non_zero() {
        assert_ne!(platform_exit_code(256), 0);
        assert_ne!(platform_exit_code(1), 0);
    }
}
