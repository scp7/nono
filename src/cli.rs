use clap::Parser;
use std::path::PathBuf;

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "EXAMPLES:
    # Allow read/write to current directory, run claude
    nono --allow . -- claude

    # Read-only access to src, write to output
    nono --read ./src --write ./output -- cargo build

    # Multiple allowed paths
    nono --allow ./project-a --allow ./project-b -- claude

    # With network access enabled
    nono --allow . --net-allow -- claude
")]
pub struct Args {
    /// Paths to allow read+write access (can be specified multiple times)
    #[arg(long, short = 'a', value_name = "PATH")]
    pub allow: Vec<PathBuf>,

    /// Paths to allow read-only access (can be specified multiple times)
    #[arg(long, short = 'r', value_name = "PATH")]
    pub read: Vec<PathBuf>,

    /// Paths to allow write-only access (can be specified multiple times)
    #[arg(long, short = 'w', value_name = "PATH")]
    pub write: Vec<PathBuf>,

    /// Enable network access (binary: all outbound allowed when flag is present)
    /// Note: Per-host filtering not supported by OS sandbox; this is on/off only
    #[arg(long)]
    pub net_allow: bool,

    /// Configuration file path
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Dry run - show what would be sandboxed without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Command to run inside the sandbox (everything after --)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

impl Args {
    /// Check if any filesystem capabilities are specified
    pub fn has_fs_caps(&self) -> bool {
        !self.allow.is_empty() || !self.read.is_empty() || !self.write.is_empty()
    }

    /// Check if network access is enabled
    pub fn has_net_caps(&self) -> bool {
        self.net_allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_args() {
        let args = Args::parse_from(["nono", "--allow", ".", "--", "echo", "hello"]);
        assert_eq!(args.allow.len(), 1);
        assert_eq!(args.command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_multiple_paths() {
        let args = Args::parse_from([
            "nono",
            "--allow", "./src",
            "--allow", "./docs",
            "--read", "/usr/share",
            "--",
            "ls",
        ]);
        assert_eq!(args.allow.len(), 2);
        assert_eq!(args.read.len(), 1);
    }

    #[test]
    fn test_has_fs_caps() {
        let args = Args::parse_from(["nono", "--allow", ".", "--", "ls"]);
        assert!(args.has_fs_caps());

        let args_empty = Args::parse_from(["nono", "--", "ls"]);
        assert!(!args_empty.has_fs_caps());
    }
}
