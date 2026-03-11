//! Post-exit interactive review/restore UI for the rollback system
//!
//! Presents the user with a summary of changes made during the session
//! and offers to restore to the initial state.

use crate::theme;
use colored::Colorize;
use nono::undo::{Change, ChangeType, SnapshotManager, SnapshotManifest};
use nono::Result;
use std::io::{BufRead, IsTerminal, Write};

/// Run the post-exit rollback review UI.
///
/// Shows a change summary and prompts the user to restore or exit.
/// Returns `true` if the user chose to restore.
pub fn review_and_restore(
    manager: &SnapshotManager,
    baseline: &SnapshotManifest,
    changes: &[Change],
) -> Result<bool> {
    let t = theme::current();
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }

    print_change_details(changes);

    eprint!(
        "{} {}",
        "nono".truecolor(t.brand.0, t.brand.1, t.brand.2).bold(),
        "Restore to initial state? [y/N]: ".truecolor(t.text.0, t.text.1, t.text.2)
    );
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin
        .lock()
        .read_line(&mut input)
        .map_err(nono::NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        eprintln!(
            "{} {}",
            "nono".truecolor(t.brand.0, t.brand.1, t.brand.2).bold(),
            "Restoring...".truecolor(t.text.0, t.text.1, t.text.2)
        );

        let applied = manager.restore_to(baseline)?;

        eprintln!(
            "{} Restored {} files.",
            "nono".truecolor(t.brand.0, t.brand.1, t.brand.2).bold(),
            applied.len()
        );
        Ok(true)
    } else {
        eprintln!(
            "{} {}",
            "nono".truecolor(t.brand.0, t.brand.1, t.brand.2).bold(),
            "Exiting without restoring.".truecolor(t.subtext.0, t.subtext.1, t.subtext.2)
        );
        Ok(false)
    }
}

/// Print details of each change
fn print_change_details(changes: &[Change]) {
    let t = theme::current();
    eprintln!(
        "{} {}",
        "nono".truecolor(t.brand.0, t.brand.1, t.brand.2).bold(),
        "Changes:".truecolor(t.text.0, t.text.1, t.text.2).bold()
    );

    for change in changes {
        let symbol = match change.change_type {
            ChangeType::Created => "+".truecolor(t.green.0, t.green.1, t.green.2),
            ChangeType::Modified => "~".truecolor(t.yellow.0, t.yellow.1, t.yellow.2),
            ChangeType::Deleted => "-".truecolor(t.red.0, t.red.1, t.red.2),
            ChangeType::PermissionsChanged => "p".truecolor(t.subtext.0, t.subtext.1, t.subtext.2),
        };

        let label = match change.change_type {
            ChangeType::Created => "created",
            ChangeType::Modified => "modified",
            ChangeType::Deleted => "deleted",
            ChangeType::PermissionsChanged => "permissions",
        };

        let size_info = change
            .size_delta
            .map(|delta| match delta.cmp(&0) {
                std::cmp::Ordering::Greater => format!(" (+{delta} bytes)"),
                std::cmp::Ordering::Less => format!(" ({delta} bytes)"),
                std::cmp::Ordering::Equal => String::new(),
            })
            .unwrap_or_default();

        eprintln!(
            "  {} {} ({}){}",
            symbol,
            change.path.display(),
            label.truecolor(t.subtext.0, t.subtext.1, t.subtext.2),
            size_info.truecolor(t.overlay.0, t.overlay.1, t.overlay.2)
        );
    }
    eprintln!();
}
