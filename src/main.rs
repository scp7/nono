mod capability;
mod cli;
mod error;
mod profile;
mod sandbox;

use capability::CapabilitySet;
use clap::Parser;
use cli::{Cli, Commands, RunArgs, WhyArgs};
use error::{NonoError, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// List of sensitive paths that are always blocked
const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.npmrc",
    "~/.git-credentials",
    "~/.netrc",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.bash_history",
    "~/.zsh_history",
    "~/Library/Keychains",
    "~/.credentials",
    "~/.secrets",
    "~/.azure",
    "~/.gcloud",
    "~/.config/gcloud",
    "~/.password-store",
    "~/.1password",
    "~/.keys",
    "~/.pki",
    "~/.terraform.d",
    "~/.vault-token",
];

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    if let Err(e) = run() {
        error!("{}", e);
        eprintln!("nono: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => run_sandbox(*args),
        Commands::Why(args) => run_why(args),
    }
}

/// Check why a path would be blocked or allowed
fn run_why(args: WhyArgs) -> Result<()> {
    let path = &args.path;
    let path_str = path.display().to_string();

    // Expand ~ in the input path for comparison
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded_path = if path_str.starts_with("~/") {
        path_str.replacen("~", &home, 1)
    } else if path_str == "~" {
        home.clone()
    } else {
        path_str.clone()
    };

    // Check if path is in sensitive paths list
    for sensitive in SENSITIVE_PATHS {
        let expanded_sensitive = sensitive.replace('~', &home);

        // Check if the path matches or is under a sensitive path
        if expanded_path == expanded_sensitive
            || expanded_path.starts_with(&format!("{}/", expanded_sensitive))
        {
            println!("BLOCKED: {} is a sensitive path", path.display());
            println!();
            println!("Reason: This path is in the always-blocked list because it may contain:");
            println!("  - Credentials (API keys, tokens, passwords)");
            println!("  - Private keys (SSH, GPG, TLS)");
            println!("  - Shell configuration (which often embeds secrets)");
            println!();
            if args.suggest {
                let flag = if path.is_file() || !Path::new(&expanded_path).exists() {
                    "--read-file"
                } else {
                    "--read"
                };
                println!(
                    "To allow access, re-run nono with: {} {}",
                    flag,
                    path.display()
                );
                println!("WARNING: Granting access to sensitive paths can expose secrets to untrusted code.");
            }
            return Ok(());
        }
    }

    // Check if path exists
    let canonical = if Path::new(&expanded_path).exists() {
        Path::new(&expanded_path)
            .canonicalize()
            .ok()
            .map(|p| p.display().to_string())
    } else {
        None
    };

    // Not in sensitive list - would depend on explicit grants
    println!("NOT BLOCKED (by default): {}", path.display());
    if let Some(ref canon) = canonical {
        println!("Resolved path: {}", canon);
    }
    println!();
    println!("This path is not in the sensitive paths list.");
    println!("Access depends on what --allow/--read/--write flags are passed to 'nono run'.");
    println!();

    if args.suggest {
        println!("To grant access:");
        if Path::new(&expanded_path).is_file() {
            println!(
                "  Read-only:   nono run --read-file {} -- <command>",
                path.display()
            );
            println!(
                "  Write-only:  nono run --write-file {} -- <command>",
                path.display()
            );
            println!(
                "  Read+Write:  nono run --allow-file {} -- <command>",
                path.display()
            );
        } else if Path::new(&expanded_path).is_dir() {
            println!(
                "  Read-only:   nono run --read {} -- <command>",
                path.display()
            );
            println!(
                "  Write-only:  nono run --write {} -- <command>",
                path.display()
            );
            println!(
                "  Read+Write:  nono run --allow {} -- <command>",
                path.display()
            );
        } else {
            println!("  (path does not exist - use file or directory flags as appropriate)");
            println!("  For directories: --read, --write, --allow");
            println!("  For files:       --read-file, --write-file, --allow-file");
        }
    }

    Ok(())
}

/// Run a command inside the sandbox
fn run_sandbox(args: RunArgs) -> Result<()> {
    // Set log level based on verbosity
    if args.verbose > 0 {
        match args.verbose {
            1 => std::env::set_var("RUST_LOG", "info"),
            2 => std::env::set_var("RUST_LOG", "debug"),
            _ => std::env::set_var("RUST_LOG", "trace"),
        }
    }

    // Check if we have a command to run
    if args.command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Build capabilities from profile or arguments
    let caps = if let Some(ref profile_name) = args.profile {
        let prof = profile::load_profile(profile_name, args.trust_unsigned)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        CapabilitySet::from_profile(&prof, &workdir, &args)?
    } else {
        CapabilitySet::from_args(&args)?
    };

    // Check if any capabilities are specified (must have fs or network)
    // Network is allowed by default, so only error if no fs AND network is blocked
    if !caps.has_fs() && caps.net_block {
        return Err(NonoError::NoCapabilities);
    }

    // Print banner
    eprintln!("nono v{} - the opposite of yolo", env!("CARGO_PKG_VERSION"));
    eprintln!();

    // Print capability summary
    eprintln!("Capabilities:");
    for line in caps.summary().lines() {
        eprintln!("  {}", line);
    }
    eprintln!();

    // Check platform support
    if !sandbox::is_supported() {
        return Err(NonoError::SandboxInit(sandbox::support_info()));
    }

    info!("{}", sandbox::support_info());

    // Dry run mode - just show what would happen
    if args.dry_run {
        eprintln!("Dry run mode - sandbox would be applied with above capabilities");
        eprintln!("Command: {:?}", args.command);
        return Ok(());
    }

    // Apply the sandbox
    eprintln!("Applying sandbox...");
    sandbox::apply(&caps)?;
    eprintln!("Sandbox active. Restrictions are now in effect.");
    eprintln!();

    // Execute the command
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    info!("Executing: {} {:?}", program, cmd_args);

    // Build environment variables for agent awareness
    let allowed_paths = if caps.fs.is_empty() {
        "(none)".to_string()
    } else {
        caps.fs
            .iter()
            .map(|c| format!("{}[{}]", c.resolved.display(), c.access))
            .collect::<Vec<_>>()
            .join(":")
    };

    let blocked_paths = SENSITIVE_PATHS.join(":");

    let nono_context = format!(
        "You are running inside the nono sandbox (v{}). \
If you see 'Operation not permitted', 'Permission denied', or EPERM errors on file operations, \
this is nono blocking access, NOT macOS TCC or filesystem permissions. \
Blocked sensitive paths: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker, shell configs. \
Allowed paths: {}. Network: {}. \
To check why a specific path is blocked, run: nono why <path>. \
To request access, ask the user to re-run nono with --read/--write/--allow flags.",
        env!("CARGO_PKG_VERSION"),
        if caps.fs.is_empty() {
            "(none)".to_string()
        } else {
            caps.fs
                .iter()
                .map(|c| c.resolved.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        if caps.net_block { "blocked" } else { "allowed" }
    );

    let err = Command::new(program)
        .args(cmd_args)
        .env("NONO_ACTIVE", "1")
        .env("NONO_ALLOWED", &allowed_paths)
        .env(
            "NONO_NET",
            if caps.net_block { "blocked" } else { "allowed" },
        )
        .env("NONO_BLOCKED", &blocked_paths)
        .env(
            "NONO_HELP",
            "To request access, ask user to re-run nono with: --read <path>, --write <path>, --allow <path> for directories; --read-file, --write-file, --allow-file for single files",
        )
        .env("NONO_CONTEXT", &nono_context)
        .exec();

    // exec() only returns if there's an error
    Err(NonoError::CommandExecution(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_paths_defined() {
        assert!(!SENSITIVE_PATHS.is_empty());
        assert!(SENSITIVE_PATHS.contains(&"~/.ssh"));
        assert!(SENSITIVE_PATHS.contains(&"~/.aws"));
    }
}
