use crate::launch_runtime::{rollback_base_exclusions, RollbackLaunchOptions};
use crate::{config, output, rollback_preflight, rollback_session, rollback_ui};
use nono::{AccessMode, CapabilitySet, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::warn;

pub(crate) struct AuditState {
    pub(crate) session_id: String,
    pub(crate) session_dir: PathBuf,
}

pub(crate) struct RollbackRuntimeState {
    pub(crate) manager: nono::undo::SnapshotManager,
    pub(crate) baseline: nono::undo::SnapshotManifest,
    pub(crate) tracked_paths: Vec<PathBuf>,
    pub(crate) atomic_temp_before: HashSet<PathBuf>,
    pub(crate) session_id: String,
}

/// Lightweight snapshot state for audit-only sessions (no rollback).
///
/// Captures pre-execution merkle root so the audit trail includes a
/// cryptographic commitment to filesystem state even when rollback
/// restore is not enabled.
pub(crate) struct AuditSnapshotState {
    pub(crate) manager: nono::undo::SnapshotManager,
    pub(crate) baseline_root: nono::undo::ContentHash,
    pub(crate) tracked_paths: Vec<PathBuf>,
}

pub(crate) struct RollbackExitContext<'a> {
    pub(crate) audit_state: Option<&'a AuditState>,
    pub(crate) rollback_state: Option<RollbackRuntimeState>,
    pub(crate) audit_snapshot_state: Option<AuditSnapshotState>,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) started: &'a str,
    pub(crate) ended: &'a str,
    pub(crate) command: &'a [String],
    pub(crate) exit_code: i32,
    pub(crate) silent: bool,
    pub(crate) rollback_prompt_disabled: bool,
}

fn rollback_vcs_exclusions() -> Vec<String> {
    [".git", ".hg", ".svn"]
        .iter()
        .map(|entry| String::from(*entry))
        .collect()
}

fn rollback_exclusion_patterns(rollback: &RollbackLaunchOptions) -> Vec<String> {
    let mut patterns = if rollback.track_all {
        rollback_vcs_exclusions()
    } else {
        rollback_base_exclusions()
    };
    patterns.extend(rollback.exclude_patterns.iter().cloned());
    patterns.sort_unstable();
    patterns.dedup();
    patterns
}

fn rollback_exclusion_config(
    rollback: &RollbackLaunchOptions,
    exclude_patterns: &[String],
) -> nono::undo::ExclusionConfig {
    nono::undo::ExclusionConfig {
        use_gitignore: true,
        exclude_patterns: exclude_patterns.to_vec(),
        exclude_globs: rollback.exclude_globs.clone(),
        force_include: rollback.include.clone(),
    }
}

fn build_snapshot_manager(
    session_dir: PathBuf,
    tracked_paths: &[PathBuf],
    exclusion_config: nono::undo::ExclusionConfig,
) -> Result<nono::undo::SnapshotManager> {
    let roots = tracked_paths
        .iter()
        .map(|tracked_path| {
            let exclusion =
                nono::undo::ExclusionFilter::new(exclusion_config.clone(), tracked_path)?;
            Ok((tracked_path.clone(), exclusion))
        })
        .collect::<Result<Vec<_>>>()?;

    nono::undo::SnapshotManager::new_per_root(session_dir, roots, nono::undo::WalkBudget::default())
}

fn enforce_rollback_limits(silent: bool) {
    let config = match config::user::load_user_config() {
        Ok(Some(config)) => config,
        Ok(None) => config::user::UserConfig::default(),
        Err(e) => {
            tracing::warn!("Failed to load user config for rollback limits: {e}");
            return;
        }
    };

    let sessions = match rollback_session::discover_sessions() {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::warn!("Failed to discover sessions for limit enforcement: {e}");
            return;
        }
    };

    if sessions.is_empty() {
        return;
    }

    let max_sessions = config.rollback.max_sessions;
    let storage_bytes_f64 =
        (config.rollback.max_storage_gb.max(0.0) * 1024.0 * 1024.0 * 1024.0).min(u64::MAX as f64);
    let max_storage_bytes = storage_bytes_f64 as u64;

    let completed: Vec<&rollback_session::SessionInfo> = sessions
        .iter()
        .filter(|session| !session.is_alive)
        .collect();

    let mut pruned = 0usize;
    let mut pruned_bytes = 0u64;

    if completed.len() > max_sessions {
        for session in &completed[max_sessions..] {
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    let total = match rollback_session::total_storage_bytes() {
        Ok(total) => total,
        Err(_) => return,
    };

    if total > max_storage_bytes {
        let remaining = match rollback_session::discover_sessions() {
            Ok(sessions) => sessions,
            Err(_) => return,
        };

        let mut current_total = total;
        for session in remaining.iter().rev().filter(|session| !session.is_alive) {
            if current_total <= max_storage_bytes {
                break;
            }
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                current_total = current_total.saturating_sub(session.disk_size);
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    if pruned > 0 && !silent {
        eprintln!(
            "  Auto-pruned {} old session(s) (freed {})",
            pruned,
            rollback_session::format_bytes(pruned_bytes),
        );
    }
}

/// Create a new session directory with a unique ID.
///
/// Used by both audit and rollback to establish a session storage location.
/// When both are active, audit creates the dir and rollback shares it.
fn ensure_session_dir(rollback_destination: Option<&PathBuf>) -> Result<(String, PathBuf)> {
    let session_id = format!(
        "{}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    let rollback_root = match rollback_destination {
        Some(path) => path.clone(),
        None => {
            let home = dirs::home_dir().ok_or(nono::NonoError::HomeNotFound)?;
            home.join(".nono").join("rollbacks")
        }
    };
    let session_dir = rollback_root.join(&session_id);
    std::fs::create_dir_all(&session_dir).map_err(|e| {
        nono::NonoError::Snapshot(format!(
            "Failed to create session directory {}: {}",
            session_dir.display(),
            e
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&session_dir, perms) {
            warn!("Failed to set session directory permissions to 0700: {e}");
        }
    }

    Ok((session_id, session_dir))
}

pub(crate) fn create_audit_state(
    audit_disabled: bool,
    rollback_destination: Option<&PathBuf>,
) -> Result<Option<AuditState>> {
    if audit_disabled {
        return Ok(None);
    }

    let (session_id, session_dir) = ensure_session_dir(rollback_destination)?;

    Ok(Some(AuditState {
        session_id,
        session_dir,
    }))
}

pub(crate) fn warn_if_rollback_flags_ignored(rollback: &RollbackLaunchOptions, silent: bool) {
    if !rollback.disabled {
        return;
    }

    let has_rollback_flags = rollback.track_all
        || !rollback.include.is_empty()
        || !rollback.exclude_patterns.is_empty()
        || !rollback.exclude_globs.is_empty();
    if has_rollback_flags {
        warn!(
            "--no-rollback is active; rollback flags \
             (--rollback-all, --rollback-include, --rollback-exclude) \
             have no effect"
        );
        if !silent {
            eprintln!(
                "  [nono] Warning: --no-rollback is active; \
                 rollback customization flags have no effect."
            );
        }
    }
}

/// Derive tracked paths from capabilities: user-granted writable directories.
fn derive_tracked_paths(caps: &CapabilitySet) -> Vec<PathBuf> {
    caps.fs_capabilities()
        .iter()
        .filter(|cap| {
            !cap.is_file
                && matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
                && cap.source.is_user_intent()
        })
        .map(|cap| cap.resolved.clone())
        .collect()
}

/// Initialize lightweight audit snapshots for merkle root computation.
///
/// When rollback is not requested but audit is active, this captures a
/// pre-execution merkle root so the audit trail includes a cryptographic
/// commitment to filesystem state.
pub(crate) fn initialize_audit_snapshots(
    caps: &CapabilitySet,
    audit_state: &AuditState,
    rollback: &RollbackLaunchOptions,
) -> Result<Option<AuditSnapshotState>> {
    let tracked_paths = derive_tracked_paths(caps);
    if tracked_paths.is_empty() {
        return Ok(None);
    }

    let patterns = rollback_exclusion_patterns(rollback);
    let exclusion_config = rollback_exclusion_config(rollback, &patterns);
    let manager = build_snapshot_manager(
        audit_state.session_dir.clone(),
        &tracked_paths,
        exclusion_config,
    )?;

    let baseline_root = manager.compute_merkle_root()?;

    Ok(Some(AuditSnapshotState {
        manager,
        baseline_root,
        tracked_paths,
    }))
}

pub(crate) fn initialize_rollback_state(
    rollback: &RollbackLaunchOptions,
    caps: &CapabilitySet,
    audit_state: Option<&AuditState>,
    silent: bool,
) -> Result<Option<RollbackRuntimeState>> {
    if !rollback.requested || rollback.disabled {
        return Ok(None);
    }

    enforce_rollback_limits(silent);

    // When audit is active, share its session directory. Otherwise create
    // a standalone directory so rollback snapshots still have somewhere to
    // live (handles the --rollback --no-audit case).
    let (session_id, session_dir) = match audit_state {
        Some(state) => (state.session_id.clone(), state.session_dir.clone()),
        None => ensure_session_dir(rollback.destination.as_ref())?,
    };

    let tracked_paths = derive_tracked_paths(caps);

    if tracked_paths.is_empty() {
        return Ok(None);
    }

    let mut patterns = rollback_exclusion_patterns(rollback);
    let base_patterns = patterns.clone();
    let preflight_exclusion = nono::undo::ExclusionFilter::new(
        rollback_exclusion_config(rollback, &patterns),
        &tracked_paths[0],
    )?;

    if !rollback.track_all {
        let preflight_result = rollback_preflight::run_preflight(
            &tracked_paths,
            &preflight_exclusion,
            &rollback.skip_dirs,
        );

        if preflight_result.needs_warning() {
            let auto_excluded: Vec<&rollback_preflight::HeavyDir> = preflight_result
                .heavy_dirs
                .iter()
                .filter(|dir| !rollback.include.contains(&dir.name))
                .collect();

            if !auto_excluded.is_empty() {
                let excluded_names: Vec<String> =
                    auto_excluded.iter().map(|dir| dir.name.clone()).collect();
                let mut all_patterns = base_patterns.clone();
                all_patterns.extend(excluded_names);
                all_patterns.sort_unstable();
                all_patterns.dedup();
                patterns = all_patterns;

                if !silent {
                    rollback_preflight::print_auto_exclude_notice(
                        &auto_excluded,
                        &preflight_result,
                    );
                }
            }
        }
    }

    let mut manager = build_snapshot_manager(
        session_dir.clone(),
        &tracked_paths,
        rollback_exclusion_config(rollback, &patterns),
    )?;

    let baseline = manager.create_baseline()?;
    let atomic_temp_before = manager.collect_atomic_temp_files();

    output::print_rollback_tracking(&tracked_paths, silent);

    Ok(Some(RollbackRuntimeState {
        manager,
        baseline,
        tracked_paths,
        atomic_temp_before,
        session_id,
    }))
}

pub(crate) fn finalize_supervised_exit(ctx: RollbackExitContext<'_>) -> Result<()> {
    let RollbackExitContext {
        audit_state,
        rollback_state,
        audit_snapshot_state,
        proxy_handle,
        started,
        ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled,
    } = ctx;

    let mut network_events = proxy_handle.map_or_else(
        Vec::new,
        nono_proxy::server::ProxyHandle::drain_audit_events,
    );

    let mut audit_saved = false;

    if let Some(RollbackRuntimeState {
        mut manager,
        baseline,
        tracked_paths,
        atomic_temp_before,
        session_id: rb_session_id,
    }) = rollback_state
    {
        let (final_manifest, changes) = manager.create_incremental(&baseline)?;
        let merkle_roots = vec![baseline.merkle_root, final_manifest.merkle_root];

        let meta = nono::undo::SessionMetadata {
            session_id: rb_session_id,
            started: started.to_string(),
            ended: Some(ended.to_string()),
            command: command.to_vec(),
            tracked_paths,
            snapshot_count: manager.snapshot_count(),
            exit_code: Some(exit_code),
            merkle_roots,
            network_events: std::mem::take(&mut network_events),
        };
        manager.save_session_metadata(&meta)?;
        audit_saved = true;

        if !changes.is_empty() {
            output::print_rollback_session_summary(&changes, silent);

            if !rollback_prompt_disabled && !silent {
                let _ = rollback_ui::review_and_restore(&manager, &baseline, &changes);
            }
        }

        let _ = manager.cleanup_new_atomic_temp_files(&atomic_temp_before);
    }

    // Audit-only path: no rollback snapshots, but still compute merkle
    // roots for tamper-evidence when audit snapshot state is available.
    if !audit_saved {
        if let Some(audit_state) = audit_state {
            let (merkle_roots, tracked_paths) = match audit_snapshot_state {
                Some(snap) => {
                    let final_root = snap.manager.compute_merkle_root()?;
                    (vec![snap.baseline_root, final_root], snap.tracked_paths)
                }
                None => (Vec::new(), Vec::new()),
            };
            let meta = nono::undo::SessionMetadata {
                session_id: audit_state.session_id.clone(),
                started: started.to_string(),
                ended: Some(ended.to_string()),
                command: command.to_vec(),
                tracked_paths,
                snapshot_count: 0,
                exit_code: Some(exit_code),
                merkle_roots,
                network_events,
            };
            nono::undo::SnapshotManager::write_session_metadata(&audit_state.session_dir, &meta)?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::{CapabilitySet, CapabilitySource, FsCapability};
    use std::fs;

    #[test]
    fn create_audit_state_returns_none_when_disabled() {
        let result = create_audit_state(true, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn create_audit_state_creates_session_when_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let state = create_audit_state(false, Some(&dest)).unwrap().unwrap();

        assert!(!state.session_id.is_empty());
        assert!(state.session_dir.exists());
        assert!(state.session_dir.starts_with(tmp.path()));
    }

    #[test]
    fn ensure_session_dir_creates_dir_in_custom_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let (session_id, session_dir) = ensure_session_dir(Some(&dest)).unwrap();

        assert!(!session_id.is_empty());
        assert!(session_dir.exists());
        assert!(session_dir.starts_with(tmp.path()));
    }

    #[test]
    fn ensure_session_dir_id_contains_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let (session_id, _) = ensure_session_dir(Some(&dest)).unwrap();

        let pid = std::process::id().to_string();
        assert!(
            session_id.contains(&pid),
            "session_id '{session_id}' should contain pid '{pid}'"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_session_dir_sets_0700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().to_path_buf();

        let (_, session_dir) = ensure_session_dir(Some(&dest)).unwrap();

        let mode = std::fs::metadata(&session_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "session dir should have 0700 permissions");
    }

    #[test]
    fn initialize_audit_snapshots_respects_rollback_include_and_exclude() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tracked = tmp.path().join("tracked");
        let node_modules = tracked.join("node_modules");
        fs::create_dir_all(&node_modules).expect("create node_modules");
        fs::write(tracked.join("keep.txt"), b"keep").expect("write keep");
        fs::write(node_modules.join("pkg.json"), b"v1").expect("write package");

        let caps = CapabilitySet::new()
            .allow_path(&tracked, AccessMode::ReadWrite)
            .expect("allow tracked");
        let audit_state = AuditState {
            session_id: "test-session".to_string(),
            session_dir: tmp.path().join("session"),
        };
        fs::create_dir_all(&audit_state.session_dir).expect("create session");

        let excluded_state =
            initialize_audit_snapshots(&caps, &audit_state, &RollbackLaunchOptions::default())
                .expect("initialize excluded")
                .expect("snapshot state");

        fs::write(node_modules.join("pkg.json"), b"v2").expect("modify excluded file");
        let excluded_root = excluded_state
            .manager
            .compute_merkle_root()
            .expect("compute excluded root");
        assert_eq!(excluded_state.baseline_root, excluded_root);

        fs::write(node_modules.join("pkg.json"), b"v1").expect("restore excluded file");

        let included_rollback = RollbackLaunchOptions {
            include: vec!["node_modules".to_string()],
            ..RollbackLaunchOptions::default()
        };
        let included_state = initialize_audit_snapshots(&caps, &audit_state, &included_rollback)
            .expect("initialize included")
            .expect("snapshot state");

        fs::write(node_modules.join("pkg.json"), b"v3").expect("modify included file");
        let included_root = included_state
            .manager
            .compute_merkle_root()
            .expect("compute included root");
        assert_ne!(included_state.baseline_root, included_root);
    }

    #[test]
    fn initialize_audit_snapshots_uses_per_root_gitignore_filters() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root_a = tmp.path().join("root-a");
        let root_b = tmp.path().join("root-b");
        fs::create_dir_all(&root_a).expect("create root_a");
        fs::create_dir_all(&root_b).expect("create root_b");
        fs::write(root_a.join(".gitignore"), "ignore-a.txt\n").expect("write gitignore a");
        fs::write(root_b.join(".gitignore"), "ignore-b.txt\n").expect("write gitignore b");
        fs::write(root_a.join("ignore-a.txt"), b"a1").expect("write ignored a");
        fs::write(root_b.join("ignore-b.txt"), b"b1").expect("write ignored b");
        fs::write(root_a.join("visible.txt"), b"visible-a").expect("write visible a");
        fs::write(root_b.join("visible.txt"), b"visible-b").expect("write visible b");

        let caps = CapabilitySet::new()
            .allow_path(&root_a, AccessMode::ReadWrite)
            .and_then(|caps| caps.allow_path(&root_b, AccessMode::ReadWrite))
            .expect("allow tracked roots");
        let audit_state = AuditState {
            session_id: "test-session".to_string(),
            session_dir: tmp.path().join("session"),
        };
        fs::create_dir_all(&audit_state.session_dir).expect("create session");

        let snapshot_state = initialize_audit_snapshots(
            &caps,
            &audit_state,
            &RollbackLaunchOptions {
                track_all: true,
                ..RollbackLaunchOptions::default()
            },
        )
        .expect("initialize snapshots")
        .expect("snapshot state");

        fs::write(root_b.join("ignore-b.txt"), b"b2").expect("modify ignored b");
        let modified_root = snapshot_state
            .manager
            .compute_merkle_root()
            .expect("compute root");
        assert_eq!(snapshot_state.baseline_root, modified_root);
    }

    #[test]
    fn derive_tracked_paths_includes_profile_writable_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tracked = tmp.path().join("tracked");
        let system = tmp.path().join("system");
        let readonly = tmp.path().join("readonly");
        let file = tmp.path().join("tracked.txt");
        fs::create_dir_all(&tracked).expect("create tracked dir");
        fs::create_dir_all(&system).expect("create system dir");
        fs::create_dir_all(&readonly).expect("create readonly dir");
        fs::write(&file, b"content").expect("write tracked file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: tracked.clone(),
            resolved: tracked.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: system.clone(),
            resolved: system.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: readonly.clone(),
            resolved: readonly.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Profile,
        });
        caps.add_fs(FsCapability {
            original: file.clone(),
            resolved: file,
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        assert_eq!(derive_tracked_paths(&caps), vec![tracked]);
    }
}
