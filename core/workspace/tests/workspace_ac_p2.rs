use std::fs;
use std::io::Write;

use chrono::{Duration, Utc};
use lecture_studio_history::{
    read_jsonl_strict, ConsentPurpose, DecisionOutcome, OperationRecord, SnapshotManifest,
    SnapshotStatus, CURRENT_HISTORY_SCHEMA_VERSION,
};
use lecture_studio_security::DataClassification;
use lecture_studio_workspace::{
    CommitJournal, CommitPhase, ExchangeTask, ExchangeTaskStatus, ExternalChangeKind,
    ProjectLockGuard, ProjectMode, SourcePermissions, WorkspaceManager, WorkspaceSqliteIndex,
    CURRENT_WORKSPACE_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

#[test]
fn workspace_ac_p2_full_lifecycle_recovery_and_exchange() {
    let tmp = TempDir::new().unwrap();
    let ws_root = tmp.path().join("LectureWorkspace");
    let allowed_in = tmp.path().join("allowed_in");
    let allowed_out = tmp.path().join("allowed_out");
    let outside_dir = tmp.path().join("outside_forbidden");
    for d in [&allowed_in, &allowed_out, &outside_dir] {
        fs::create_dir_all(d).unwrap();
    }

    let ws = WorkspaceManager::init_workspace(
        &ws_root,
        vec![allowed_in.clone()],
        vec![allowed_out.clone()],
    )
    .unwrap();

    // Custom allowed input/output enforcement
    let textbook = allowed_in.join("textbook_ch1.tex");
    fs::write(&textbook, b"\\section{Linear Algebra}\n").unwrap();
    let imported = ws
        .import_source(
            &textbook,
            "p.1-10",
            SourcePermissions {
                usage: true,
                learning: false,
                export: false,
            },
            DataClassification::Internal,
            "cli_user",
        )
        .unwrap();
    assert!(ws_root.join(&imported.stored_rel_path).exists());

    let outside_secret = outside_dir.join("secret.txt");
    fs::write(&outside_secret, b"OUTSIDE").unwrap();
    let err_in = ws
        .import_source(
            &outside_secret,
            "p.1",
            SourcePermissions {
                usage: true,
                learning: false,
                export: false,
            },
            DataClassification::Public,
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err_in.code(), "PATH_OUTSIDE_ALLOWED_ROOT");

    // Create project with Japanese + TeX content for FTS5 trigram test
    let initial_tex = b"\\section{\xe7\xb7\x9a\xe5\xbd\xa2\xe4\xbb\xa3\xe6\x95\xb0\xe3\x81\xae\xe5\x9f\xba\xe7\xa4\x8e}\nVector space $V$.\n";
    let proj = ws
        .create_project(
            "線形代数講義",
            ProjectMode::LatexFirst,
            "latex/main.tex",
            initial_tex,
            DataClassification::Internal,
            "cli_user",
        )
        .unwrap();
    assert_eq!(proj.revision, 1);

    // Export boundary: inside allowed_out succeeds, outside allowed_out fails
    let ok_export = allowed_out.join("main_export.tex");
    ws.export_project_file(&proj.project_id, "latex/main.tex", &ok_export, "cli_user")
        .unwrap();
    assert_eq!(fs::read(&ok_export).unwrap(), initial_tex);
    let err_out = ws
        .export_project_file(
            &proj.project_id,
            "latex/main.tex",
            &outside_dir.join("escape.tex"),
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err_out.code(), "PATH_OUTSIDE_ALLOWED_ROOT");

    // Optimistic revision conflict + stale buffer protection
    let rev2_tex = b"\\section{\xe5\xbe\xae\xe7\xa9\x8d\xe5\x88\x86\xe5\x85\xa5\xe9\x96\x80}\nRevised rev 2.\n";
    let proj_r2 = ws
        .save_project_file(
            &proj.project_id,
            "latex/main.tex",
            rev2_tex,
            1,
            Some(&sha256_hex(initial_tex)),
            "cli_user",
        )
        .unwrap();
    assert_eq!(proj_r2.revision, 2);

    let err_stale_save = ws
        .save_project_file(
            &proj.project_id,
            "latex/main.tex",
            b"STALE_OVERWRITE",
            1,
            None,
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err_stale_save.code(), "REVISION_CONFLICT");
    assert_eq!(
        fs::read(
            ws.project_dir(&proj.project_id)
                .unwrap()
                .join("latex/main.tex")
        )
        .unwrap(),
        rev2_tex
    );

    // Concurrent lock contention blocks simultaneous save
    {
        let p_dir = ws.project_dir(&proj.project_id).unwrap();
        let _held_lock = ProjectLockGuard::acquire(&p_dir).unwrap();
        let err_lock = ws
            .save_project_file(
                &proj.project_id,
                "latex/main.tex",
                b"LOCKED",
                2,
                None,
                "cli_user",
            )
            .unwrap_err();
        assert_eq!(err_lock.code(), "LOCK_CONTENTION");
    }

    // External modification detection prevents blind overwrite and imports ONLY observed diff
    let main_abs = ws
        .project_dir(&proj.project_id)
        .unwrap()
        .join("latex/main.tex");
    let ext_tex = b"\\section{\xe5\xa4\x96\xe9\x83\xa8\xe7\xb7\xa8\xe9\x9b\x86\xe3\x81\xae\xe5\xb7\xae\xe5\x88\x86}\nEdited externally.\n";
    fs::write(&main_abs, ext_tex).unwrap();
    let err_ext = ws
        .save_project_file(
            &proj.project_id,
            "latex/main.tex",
            b"OVERWRITE",
            2,
            None,
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err_ext.code(), "EXTERNAL_MODIFICATION_DETECTED");

    let ext_rep = ws
        .import_external_changes(&proj.project_id, "cli_user")
        .unwrap();
    assert_eq!(ext_rep.new_revision, 3);
    assert_eq!(ext_rep.observed_changes.len(), 1);
    assert_eq!(
        ext_rep.observed_changes[0].kind,
        ExternalChangeKind::Modified
    );
    let ops = lecture_studio_history::read_jsonl_strict::<lecture_studio_history::OperationRecord>(
        &ws.project_dir(&proj.project_id)
            .unwrap()
            .join("history/operations.jsonl"),
    )
    .unwrap();
    let last_op = ops.last().unwrap();
    assert_eq!(
        last_op.origin_type,
        lecture_studio_history::OriginType::ExternalDiff
    );
    assert!(last_op
        .note
        .as_deref()
        .unwrap_or("")
        .contains("not_fabricated"));

    // Snapshot restore with pre-restore backup
    let snaps_dir = ws
        .project_dir(&proj.project_id)
        .unwrap()
        .join("history/snapshots");
    let first_snap_id = fs::read_dir(&snaps_dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                return None;
            }
            let m: SnapshotManifest = serde_json::from_str(&fs::read_to_string(&p).ok()?).ok()?;
            (m.revision == 1 && m.creation_status == SnapshotStatus::Complete)
                .then_some(m.snapshot_id)
        })
        .next()
        .unwrap();
    let (proj_restored, rest_rep) = ws
        .restore_project_snapshot(&proj.project_id, &first_snap_id, "cli_user")
        .unwrap();
    assert_eq!(proj_restored.revision, 4);
    assert_eq!(fs::read(&main_abs).unwrap(), initial_tex);
    assert!(snaps_dir
        .join(format!("{}.json", rest_rep.pre_restore_backup_id))
        .exists());

    // Exchange inbox boundary, actor spoof, expiry, idempotency, conflict, and proposal separation
    let err_outside_ex = ws
        .ingest_exchange_task(&outside_dir.join("evil_task.json"))
        .unwrap_err();
    assert_eq!(err_outside_ex.code(), "EXCHANGE_BOUNDARY_VIOLATION");

    let inbox = ws_root.join("exchange/inbox");
    let spoof_task = ExchangeTask {
        schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
        task_id: "task-spoof".to_string(),
        request_id: "req-spoof".to_string(),
        project_id: proj.project_id.clone(),
        actor: "cli_user".to_string(),
        allowed_operation: "propose_edit".to_string(),
        target_rel_path: "latex/main.tex".to_string(),
        target_revision: 4,
        input_hash: sha256_hex(initial_tex),
        status: ExchangeTaskStatus::Pending,
        expires_at_utc: (Utc::now() + Duration::hours(1)).to_rfc3339(),
        output_hash: None,
        audit_id: None,
        proposal_content: "SPOOF".to_string(),
    };
    let spoof_path = inbox.join("spoof.json");
    fs::write(&spoof_path, serde_json::to_string(&spoof_task).unwrap()).unwrap();
    assert_eq!(
        ws.ingest_exchange_task(&spoof_path).unwrap_err().code(),
        "ACTOR_SPOOF"
    );

    let stale_task = ExchangeTask {
        task_id: "task-stale".to_string(),
        request_id: "req-stale".to_string(),
        actor: "external_agent".to_string(),
        target_revision: 2,
        ..spoof_task.clone()
    };
    let stale_path = inbox.join("stale.json");
    fs::write(&stale_path, serde_json::to_string(&stale_task).unwrap()).unwrap();
    assert_eq!(
        ws.ingest_exchange_task(&stale_path).unwrap_err().code(),
        "REVISION_CONFLICT"
    );

    let prop_text = "\\section{線形代数の基礎}\nProposal from external agent.\n";
    let valid_task = ExchangeTask {
        task_id: "task-valid-1".to_string(),
        request_id: "req-valid-1".to_string(),
        actor: "external_agent".to_string(),
        target_revision: 4,
        proposal_content: prop_text.to_string(),
        ..spoof_task
    };
    let valid_path = inbox.join("valid_1.json");
    fs::write(&valid_path, serde_json::to_string(&valid_task).unwrap()).unwrap();
    let staged = ws.ingest_exchange_task(&valid_path).unwrap();
    assert_eq!(staged.status, ExchangeTaskStatus::Proposed);
    // Proposal alone MUST NOT touch canonical source!
    assert_eq!(fs::read(&main_abs).unwrap(), initial_tex);
    // Duplicate replay rejected persistently even on freshly opened WorkspaceManager
    let ws_reopened = WorkspaceManager::open_workspace(&ws_root).unwrap();
    let dup_err = ws_reopened.ingest_exchange_task(&valid_path).unwrap_err();
    assert_eq!(dup_err.code(), "DUPLICATE_TASK");

    // Apply teacher decision (Accepted) with explicit rationale
    let applied = ws_reopened
        .apply_exchange_proposal(
            &proj.project_id,
            "task-valid-1",
            DecisionOutcome::Accepted,
            Some("Verified proof clarity".to_string()),
            None,
            "cli_user",
        )
        .unwrap();
    assert_eq!(applied.status, ExchangeTaskStatus::Accepted);
    assert_eq!(fs::read_to_string(&main_abs).unwrap(), prop_text);
    // Double application refused
    assert_eq!(
        ws_reopened
            .apply_exchange_proposal(
                &proj.project_id,
                "task-valid-1",
                DecisionOutcome::Accepted,
                None,
                None,
                "cli_user"
            )
            .unwrap_err()
            .code(),
        "DUPLICATE_TASK"
    );

    // Grant distinct consent + verify SQLite FTS5 trigram search survives DB deletion & corruption
    ws_reopened
        .consent_store()
        .grant(
            &proj.project_id,
            ConsentPurpose::HistorySave,
            "teacher",
            "1.0.0",
        )
        .unwrap();
    let hits = ws_reopened.sqlite_index().search_files("線形代数").unwrap();
    assert!(!hits.is_empty());

    let db_path = ws_root.join("cache/workspace_index.sqlite");
    fs::write(&db_path, b"NOT_A_VALID_SQLITE_DB_CORRUPTED").unwrap();
    assert!(!WorkspaceSqliteIndex::new(&db_path)
        .verify_integrity()
        .unwrap());

    // Simulate crash-truncated JSONL tail, while user's hidden .tmp file MUST remain untouched
    {
        let mut fh = fs::OpenOptions::new()
            .append(true)
            .open(
                ws.project_dir(&proj.project_id)
                    .unwrap()
                    .join("history/operations.jsonl"),
            )
            .unwrap();
        writeln!(fh, "{{\"truncated_crash\": ").unwrap();
    }
    let user_tmp = ws
        .project_dir(&proj.project_id)
        .unwrap()
        .join("assets/.user-data.tmp");
    fs::write(&user_tmp, b"USER_DATA_MUST_SURVIVE").unwrap();

    let rec = ws_reopened.recover_workspace().unwrap();
    assert_eq!(rec.project_history_dropped_lines, 1);
    assert_eq!(rec.removed_orphan_temps, 0);
    assert_eq!(fs::read(&user_tmp).unwrap(), b"USER_DATA_MUST_SURVIVE");
    assert!(rec.index_rebuilt);
    assert!(ws_reopened.sqlite_index().verify_integrity().unwrap());
    assert!(!ws_reopened
        .sqlite_index()
        .search_files("線形代数")
        .unwrap()
        .is_empty());
    assert!(ws_reopened
        .consent_store()
        .has_active_consent(&proj.project_id, ConsentPurpose::HistorySave)
        .unwrap());
    assert!(!ws_reopened
        .consent_store()
        .has_active_consent(&proj.project_id, ConsentPurpose::LearningTrain)
        .unwrap());

    // Verify incompatible workspace schema_version is refused rather than silently misread
    let ws_yaml_path = ws_root.join("workspace.yaml");
    let orig_yaml = fs::read_to_string(&ws_yaml_path).unwrap();
    fs::write(
        &ws_yaml_path,
        orig_yaml.replace("schema_version: 1.0.0", "schema_version: 99.0.0"),
    )
    .unwrap();
    let incompat_err = WorkspaceManager::open_workspace(&ws_root)
        .err()
        .expect("incompatible schema_version must be refused");
    assert_eq!(incompat_err.code(), "SCHEMA_VERSION_INCOMPATIBLE");
    // Double-check CURRENT_HISTORY_SCHEMA_VERSION constant used cleanly
    assert_eq!(CURRENT_HISTORY_SCHEMA_VERSION, "1.0.0");
}

fn setup_basic_workspace() -> (TempDir, WorkspaceManager, String) {
    let tmp = TempDir::new().unwrap();
    let ws_root = tmp.path().join("ws");
    let in_r = tmp.path().join("in");
    let out_r = tmp.path().join("out");
    fs::create_dir_all(&in_r).unwrap();
    fs::create_dir_all(&out_r).unwrap();
    let ws = WorkspaceManager::init_workspace(&ws_root, vec![in_r], vec![out_r]).unwrap();
    let proj = ws
        .create_project(
            "Safety Test Project",
            ProjectMode::LatexFirst,
            "latex/main.tex",
            b"\\section{Initial v1}\n",
            DataClassification::Internal,
            "cli_user",
        )
        .unwrap();
    (tmp, ws, proj.project_id)
}

#[test]
fn recover_workspace_preserves_user_hidden_tmp_files_and_skips_active_locked_projects() {
    let (_tmp, ws, pid) = setup_basic_workspace();
    let p_dir = ws.project_dir(&pid).unwrap();

    // User's own hidden .tmp files in assets/ and latex/ MUST never be deleted by recover_workspace
    let user_asset_tmp = p_dir.join("assets/.user-data.tmp");
    let user_latex_tmp = p_dir.join("latex/.notes.tmp");
    fs::write(&user_asset_tmp, b"IMPORTANT_USER_TEMP").unwrap();
    fs::write(&user_latex_tmp, b"IMPORTANT_LATEX_TEMP").unwrap();

    // While a live OS lock is held (simulating active save), recover_workspace skips the locked project
    let active_staged = p_dir.join("history/.ls-stage-active.tmp");
    fs::write(&active_staged, b"ACTIVE_SAVE_IN_PROGRESS").unwrap();
    let active_journal = CommitJournal {
        schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
        tx_id: "active".to_string(),
        project_id: pid.clone(),
        target_rel_path: "latex/main.tex".to_string(),
        base_revision: 1,
        target_revision: 2,
        before_hash: Some(sha256_hex(b"\\section{Initial v1}\n")),
        after_hash: sha256_hex(b"ACTIVE_SAVE_IN_PROGRESS"),
        after_size_bytes: 23,
        actor: "cli_user".to_string(),
        op_event_id: "op-active".to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        staged_temp_rel_path: "history/.ls-stage-active.tmp".to_string(),
        audit_id: None,
        phase: CommitPhase::Prepared,
        conflict_reason: None,
    };
    fs::write(
        p_dir.join("history/.commit_journal.json"),
        serde_json::to_string_pretty(&active_journal).unwrap(),
    )
    .unwrap();

    {
        let _active_lock = ProjectLockGuard::acquire(&p_dir).unwrap();
        let rep_locked = ws.recover_workspace().unwrap();
        assert_eq!(rep_locked.skipped_locked_projects, 1);
        assert_eq!(rep_locked.rolled_back_journals, 0);
        assert!(active_staged.exists());
    }

    // Once active lock is released, recovery rolls back the Prepared app journal & cleans ONLY its temp
    let rep_unlocked = ws.recover_workspace().unwrap();
    assert_eq!(rep_unlocked.skipped_locked_projects, 0);
    assert_eq!(rep_unlocked.rolled_back_journals, 1);
    assert_eq!(rep_unlocked.removed_orphan_temps, 1);
    assert!(!active_staged.exists());
    assert!(!p_dir.join("history/.commit_journal.json").exists());
    assert_eq!(fs::read(&user_asset_tmp).unwrap(), b"IMPORTANT_USER_TEMP");
    assert_eq!(fs::read(&user_latex_tmp).unwrap(), b"IMPORTANT_LATEX_TEMP");
}

#[test]
fn stale_lock_file_from_dead_pid_recovers_automatically_while_live_lock_contends() {
    let (_tmp, ws, pid) = setup_basic_workspace();
    let p_dir = ws.project_dir(&pid).unwrap();
    let lock_path = p_dir.join(".project.lock");

    // Simulate process crash leaving behind a stale lock file referencing a non-existent PID
    fs::write(&lock_path, b"pid=999999\n").unwrap();

    let rep = ws.recover_workspace().unwrap();
    assert_eq!(rep.skipped_locked_projects, 0);

    let saved = ws
        .save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{After Dead Lock}\n",
            1,
            None,
            "cli_user",
        )
        .unwrap();
    assert_eq!(saved.revision, 2);

    // Live held OS lock MUST still enforce LOCK_CONTENTION
    let _live = ProjectLockGuard::acquire(&p_dir).unwrap();
    let err = ws
        .save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{Should Contend}\n",
            2,
            None,
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err.code(), "LOCK_CONTENTION");
}

#[test]
fn audit_failure_leaves_canonical_file_revision_and_history_unchanged() {
    let (tmp, ws, pid) = setup_basic_workspace();
    let p_dir = ws.project_dir(&pid).unwrap();
    let main_abs = p_dir.join("latex/main.tex");
    let audit_path = ws.audit_log().path().to_path_buf();
    let ops_path = p_dir.join("history/operations.jsonl");

    let ops_before = read_jsonl_strict::<OperationRecord>(&ops_path)
        .unwrap()
        .len();
    let rev_before = ws.load_project(&pid).unwrap().revision;
    let content_before = fs::read(&main_abs).unwrap();

    // Make audit log unwritable (read-only) so mandatory audit fails
    let mut perms = fs::metadata(&audit_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&audit_path, perms).unwrap();

    let err_save = ws
        .save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{MUST_NOT_COMMIT}\n",
            rev_before,
            None,
            "cli_user",
        )
        .unwrap_err();
    assert_eq!(err_save.code(), "AUDIT_FAILURE");

    // Canonical source, project revision, and operation history must remain 100% unchanged
    assert_eq!(fs::read(&main_abs).unwrap(), content_before);
    assert_eq!(ws.load_project(&pid).unwrap().revision, rev_before);
    assert_eq!(
        read_jsonl_strict::<OperationRecord>(&ops_path)
            .unwrap()
            .len(),
        ops_before
    );
    assert!(!p_dir.join("history/.commit_journal.json").exists());

    // Export must also abort before writing to destination when audit log is unwritable
    let out_file = tmp.path().join("out/must_not_export.tex");
    let err_export = ws
        .export_project_file(&pid, "latex/main.tex", &out_file, "cli_user")
        .unwrap_err();
    assert_eq!(err_export.code(), "AUDIT_FAILURE");
    assert!(!out_file.exists());

    // Restore audit log writability and confirm subsequent save succeeds cleanly
    let mut perms_rw = fs::metadata(&audit_path).unwrap().permissions();
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    perms_rw.set_readonly(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms_rw.set_mode(0o644);
    }
    fs::set_permissions(&audit_path, perms_rw).unwrap();

    let saved = ws
        .save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{Recovered Clean Save}\n",
            rev_before,
            None,
            "cli_user",
        )
        .unwrap();
    assert_eq!(saved.revision, rev_before + 1);
}

#[test]
fn commit_journal_recovers_mid_save_crashes_at_every_stage() {
    let (_tmp, ws, pid) = setup_basic_workspace();
    let p_dir = ws.project_dir(&pid).unwrap();
    let main_abs = p_dir.join("latex/main.tex");
    let ops_path = p_dir.join("history/operations.jsonl");
    let journal_path = p_dir.join("history/.commit_journal.json");

    // Stage A: crash during Prepared phase (before audit) -> rollback leaves v1 untouched
    let staged_a_rel = "history/.ls-stage-crashA.tmp";
    fs::write(
        p_dir.join(staged_a_rel),
        b"\\section{Uncommitted Crash A}\n",
    )
    .unwrap();
    let j_a = CommitJournal {
        schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
        tx_id: "crashA".to_string(),
        project_id: pid.clone(),
        target_rel_path: "latex/main.tex".to_string(),
        base_revision: 1,
        target_revision: 2,
        before_hash: Some(sha256_hex(b"\\section{Initial v1}\n")),
        after_hash: sha256_hex(b"\\section{Uncommitted Crash A}\n"),
        after_size_bytes: 29,
        actor: "cli_user".to_string(),
        op_event_id: "op-crash-a".to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        staged_temp_rel_path: staged_a_rel.to_string(),
        audit_id: None,
        phase: CommitPhase::Prepared,
        conflict_reason: None,
    };
    fs::write(&journal_path, serde_json::to_string_pretty(&j_a).unwrap()).unwrap();
    assert_eq!(
        ws.save_project_file(&pid, "latex/main.tex", b"BLOCKED", 1, None, "cli_user")
            .unwrap_err()
            .code(),
        "RECOVERY_REQUIRED"
    );

    let rep_a = ws.recover_workspace().unwrap();
    assert_eq!(rep_a.rolled_back_journals, 1);
    assert_eq!(rep_a.rolled_forward_journals, 0);
    assert_eq!(fs::read(&main_abs).unwrap(), b"\\section{Initial v1}\n");
    assert_eq!(ws.load_project(&pid).unwrap().revision, 1);
    assert!(!journal_path.exists());

    // Stage B: Audited crash AFTER canonical file write, BEFORE project.yaml and operations.jsonl update
    let rev2_bytes = b"\\section{Committed Via Journal B}\n";
    let staged_b_rel = "history/.ls-stage-crashB.tmp";
    fs::write(p_dir.join(staged_b_rel), rev2_bytes).unwrap();
    fs::write(&main_abs, rev2_bytes).unwrap();
    let j_b = CommitJournal {
        schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
        tx_id: "crashB".to_string(),
        project_id: pid.clone(),
        target_rel_path: "latex/main.tex".to_string(),
        base_revision: 1,
        target_revision: 2,
        before_hash: Some(sha256_hex(b"\\section{Initial v1}\n")),
        after_hash: sha256_hex(rev2_bytes),
        after_size_bytes: rev2_bytes.len() as u64,
        actor: "cli_user".to_string(),
        op_event_id: "op-crash-b".to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        staged_temp_rel_path: staged_b_rel.to_string(),
        audit_id: Some("aud-b".to_string()),
        phase: CommitPhase::Audited,
        conflict_reason: None,
    };
    fs::write(&journal_path, serde_json::to_string_pretty(&j_b).unwrap()).unwrap();

    let rep_b = ws.recover_workspace().unwrap();
    assert_eq!(rep_b.rolled_forward_journals, 1);
    assert_eq!(ws.load_project(&pid).unwrap().revision, 2);
    assert_eq!(fs::read(&main_abs).unwrap(), rev2_bytes);
    let ops_b = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
    assert!(ops_b.iter().any(|op| op.event_id == "op-crash-b"));

    // Stage C: Audited crash AFTER project.yaml update, BEFORE operations.jsonl append
    let rev3_bytes = b"\\section{Committed Via Journal C}\n";
    let staged_c_rel = "history/.ls-stage-crashC.tmp";
    fs::write(p_dir.join(staged_c_rel), rev3_bytes).unwrap();
    fs::write(&main_abs, rev3_bytes).unwrap();
    let mut proj_c = ws.load_project(&pid).unwrap();
    proj_c.revision = 3;
    proj_c
        .tracked_files
        .get_mut("latex/main.tex")
        .unwrap()
        .sha256 = sha256_hex(rev3_bytes);
    fs::write(
        p_dir.join("project.yaml"),
        serde_yaml::to_string(&proj_c).unwrap(),
    )
    .unwrap();
    let j_c = CommitJournal {
        schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
        tx_id: "crashC".to_string(),
        project_id: pid.clone(),
        target_rel_path: "latex/main.tex".to_string(),
        base_revision: 2,
        target_revision: 3,
        before_hash: Some(sha256_hex(rev2_bytes)),
        after_hash: sha256_hex(rev3_bytes),
        after_size_bytes: rev3_bytes.len() as u64,
        actor: "cli_user".to_string(),
        op_event_id: "op-crash-c".to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        staged_temp_rel_path: staged_c_rel.to_string(),
        audit_id: Some("aud-c".to_string()),
        phase: CommitPhase::Audited,
        conflict_reason: None,
    };
    fs::write(&journal_path, serde_json::to_string_pretty(&j_c).unwrap()).unwrap();

    let rep_c1 = ws.recover_workspace().unwrap();
    assert_eq!(rep_c1.rolled_forward_journals, 1);
    let ops_c = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
    assert_eq!(
        ops_c
            .iter()
            .filter(|op| op.event_id == "op-crash-c")
            .count(),
        1
    );
    // Re-running recover_workspace must be completely idempotent
    let rep_c2 = ws.recover_workspace().unwrap();
    assert_eq!(rep_c2.rolled_forward_journals, 0);
    let ops_c2 = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
    assert_eq!(
        ops_c2
            .iter()
            .filter(|op| op.event_id == "op-crash-c")
            .count(),
        1
    );

    // Next save at revision 3 works seamlessly
    let saved4 = ws
        .save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{Rev 4}\n",
            3,
            None,
            "cli_user",
        )
        .unwrap();
    assert_eq!(saved4.revision, 4);
}

#[test]
fn workspace_and_snapshots_work_on_normal_and_deep_temp_paths() {
    // 1. Standard non-extended temp path directly under std::env::temp_dir()
    let normal_base =
        std::env::temp_dir().join(format!("ls_norm_{}", uuid::Uuid::new_v4().simple()));
    let _cleanup_guard = tempfile::Builder::new()
        .prefix("ls_guard_")
        .tempdir()
        .unwrap();
    let ws_norm = normal_base.join("workspace");
    let in_norm = normal_base.join("in");
    let out_norm = normal_base.join("out");
    fs::create_dir_all(&in_norm).unwrap();
    fs::create_dir_all(&out_norm).unwrap();

    let mgr = WorkspaceManager::init_workspace(&ws_norm, vec![in_norm], vec![out_norm]).unwrap();
    let proj = mgr
        .create_project(
            "Normal Path Test",
            ProjectMode::TypstFirst,
            "typst/main.typ",
            b"= Normal Path Typst\n",
            DataClassification::Public,
            "cli_user",
        )
        .unwrap();
    let saved = mgr
        .save_project_file(
            &proj.project_id,
            "typst/main.typ",
            b"= Updated Typst Rev2\n",
            1,
            None,
            "cli_user",
        )
        .unwrap();
    let snap = mgr
        .create_project_snapshot(
            &proj.project_id,
            Some("normal-temp-snap".to_string()),
            "cli_user",
        )
        .unwrap();
    let (restored, _) = mgr
        .restore_project_snapshot(&proj.project_id, &snap.snapshot_id, "cli_user")
        .unwrap();
    assert_eq!(saved.revision, 2);
    assert_eq!(restored.revision, 3);
    let _ = fs::remove_dir_all(&normal_base);

    // 2. Deep >260-char workspace root path on Windows
    let tmp = TempDir::new().unwrap();
    let deep_root = tmp
        .path()
        .join("deep_a".repeat(12))
        .join("deep_b".repeat(12))
        .join("LectureWorkspace");
    let deep_in = tmp.path().join("in");
    let deep_out = tmp.path().join("out");
    fs::create_dir_all(&deep_in).unwrap();
    fs::create_dir_all(&deep_out).unwrap();
    assert!(deep_root.to_string_lossy().len() > 160);

    let deep_mgr =
        WorkspaceManager::init_workspace(&deep_root, vec![deep_in], vec![deep_out]).unwrap();
    let deep_proj = deep_mgr
        .create_project(
            "Deep Path Project",
            ProjectMode::LatexFirst,
            "latex/section_deep/main_file_exceeding_legacy_max_path_limits.tex",
            b"\\section{Deep Path Content}\n",
            DataClassification::Internal,
            "cli_user",
        )
        .unwrap();
    assert!(
        deep_mgr
            .project_dir(&deep_proj.project_id)
            .unwrap()
            .join("history/snapshots/blobs")
            .to_string_lossy()
            .len()
            > 250
    );
    let deep_saved = deep_mgr
        .save_project_file(
            &deep_proj.project_id,
            "latex/section_deep/main_file_exceeding_legacy_max_path_limits.tex",
            b"\\section{Deep Updated}\n",
            1,
            None,
            "cli_user",
        )
        .unwrap();
    assert_eq!(deep_saved.revision, 2);
}

#[test]
fn audited_journal_recovery_preserves_external_edit_and_advanced_revision_as_conflict() {
    // 1. Post-crash external edit on canonical file (disk hash differs from both before_hash and after_hash)
    {
        let (_tmp, ws, pid) = setup_basic_workspace();
        let p_dir = ws.project_dir(&pid).unwrap();
        let main_abs = p_dir.join("latex/main.tex");
        let ops_path = p_dir.join("history/operations.jsonl");
        let journal_path = p_dir.join("history/.commit_journal.json");
        let staged_rel = "history/.ls-stage-extconflict.tmp";
        let staged_abs = p_dir.join(staged_rel);

        let v1_bytes = b"\\section{Initial v1}\n";
        let staged_v2 = b"\\section{Staged v2 After Audit}\n";
        let external_v_edit = b"\\section{User External Edit After Crash}\n";

        fs::write(&staged_abs, staged_v2).unwrap();
        let j = CommitJournal {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            tx_id: "extconflict".to_string(),
            project_id: pid.clone(),
            target_rel_path: "latex/main.tex".to_string(),
            base_revision: 1,
            target_revision: 2,
            before_hash: Some(sha256_hex(v1_bytes)),
            after_hash: sha256_hex(staged_v2),
            after_size_bytes: staged_v2.len() as u64,
            actor: "cli_user".to_string(),
            op_event_id: "op-ext-conflict".to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            staged_temp_rel_path: staged_rel.to_string(),
            audit_id: Some("aud-ext-conflict".to_string()),
            phase: CommitPhase::Audited,
            conflict_reason: None,
        };
        fs::write(&journal_path, serde_json::to_string_pretty(&j).unwrap()).unwrap();

        // Simulate external edit occurring after crash before recover_workspace runs
        fs::write(&main_abs, external_v_edit).unwrap();

        let rep = ws.recover_workspace().unwrap();
        assert_eq!(rep.conflicted_journals, 1);
        assert_eq!(rep.conflicted_projects, vec![pid.clone()]);
        assert_eq!(rep.rolled_forward_journals, 0);
        assert_eq!(rep.rolled_back_journals, 0);
        assert_eq!(rep.removed_orphan_temps, 0);

        // External edit, staged payload, and conflicted journal MUST all be preserved
        assert_eq!(fs::read(&main_abs).unwrap(), external_v_edit);
        assert!(staged_abs.exists());
        assert_eq!(fs::read(&staged_abs).unwrap(), staged_v2);
        assert!(journal_path.exists());
        let saved_j: CommitJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        assert_eq!(saved_j.phase, CommitPhase::Conflicted);
        assert!(saved_j.conflict_reason.is_some());

        // Project revision and operations history MUST NOT be mutated
        assert_eq!(ws.load_project(&pid).unwrap().revision, 1);
        let ops = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
        assert!(!ops.iter().any(|op| op.event_id == "op-ext-conflict"));

        let audit_after_first = ws.audit_log().verify_chain().unwrap();
        assert!(audit_after_first.0);
        assert!(audit_after_first.1 >= 2);

        // Re-running recover_workspace MUST remain idempotent & preserve all conflict artifacts
        let rep2 = ws.recover_workspace().unwrap();
        assert_eq!(rep2.conflicted_journals, 1);
        assert_eq!(rep2.rolled_forward_journals, 0);
        assert_eq!(fs::read(&main_abs).unwrap(), external_v_edit);
        assert_eq!(fs::read(&staged_abs).unwrap(), staged_v2);
        assert!(journal_path.exists());
        assert_eq!(ws.audit_log().verify_chain().unwrap(), audit_after_first);

        // save_project_file MUST refuse blind overwrite while conflict is held
        let err = ws
            .save_project_file(&pid, "latex/main.tex", b"BLOCKED", 1, None, "cli_user")
            .unwrap_err();
        assert_eq!(err.code(), "RECOVERY_CONFLICT");
    }

    // 2. Project revision already advanced past journal.target_revision -> conflict preserved
    {
        let (_tmp, ws, pid) = setup_basic_workspace();
        let p_dir = ws.project_dir(&pid).unwrap();
        let main_abs = p_dir.join("latex/main.tex");
        let journal_path = p_dir.join("history/.commit_journal.json");
        let staged_rel = "history/.ls-stage-revconflict.tmp";
        let staged_abs = p_dir.join(staged_rel);

        let v1_bytes = b"\\section{Initial v1}\n";
        ws.save_project_file(
            &pid,
            "latex/main.tex",
            b"\\section{Clean Rev2}\n",
            1,
            None,
            "cli_user",
        )
        .unwrap();
        let rev3_bytes = b"\\section{Clean Rev3}\n";
        ws.save_project_file(&pid, "latex/main.tex", rev3_bytes, 2, None, "cli_user")
            .unwrap();

        let stale_staged = b"\\section{Stale Journal v2}\n";
        fs::write(&staged_abs, stale_staged).unwrap();
        let j = CommitJournal {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            tx_id: "revconflict".to_string(),
            project_id: pid.clone(),
            target_rel_path: "latex/main.tex".to_string(),
            base_revision: 1,
            target_revision: 2,
            before_hash: Some(sha256_hex(v1_bytes)),
            after_hash: sha256_hex(stale_staged),
            after_size_bytes: stale_staged.len() as u64,
            actor: "cli_user".to_string(),
            op_event_id: "op-rev-conflict".to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            staged_temp_rel_path: staged_rel.to_string(),
            audit_id: Some("aud-rev-conflict".to_string()),
            phase: CommitPhase::Audited,
            conflict_reason: None,
        };
        fs::write(&journal_path, serde_json::to_string_pretty(&j).unwrap()).unwrap();

        let rep = ws.recover_workspace().unwrap();
        assert_eq!(rep.conflicted_journals, 1);
        assert_eq!(rep.rolled_forward_journals, 0);
        assert_eq!(rep.removed_orphan_temps, 0);
        assert_eq!(ws.load_project(&pid).unwrap().revision, 3);
        assert_eq!(fs::read(&main_abs).unwrap(), rev3_bytes);
        assert!(staged_abs.exists());
        assert_eq!(fs::read(&staged_abs).unwrap(), stale_staged);
        let saved_j: CommitJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        assert_eq!(saved_j.phase, CommitPhase::Conflicted);

        let err = ws
            .save_project_file(&pid, "latex/main.tex", b"BLOCKED", 3, None, "cli_user")
            .unwrap_err();
        assert_eq!(err.code(), "RECOVERY_CONFLICT");
    }

    // 3. External deletion after crash (before_hash was Some, file deleted on disk) -> conflict preserved
    {
        let (_tmp, ws, pid) = setup_basic_workspace();
        let p_dir = ws.project_dir(&pid).unwrap();
        let main_abs = p_dir.join("latex/main.tex");
        let journal_path = p_dir.join("history/.commit_journal.json");
        let staged_rel = "history/.ls-stage-delconflict.tmp";
        let staged_abs = p_dir.join(staged_rel);

        let v1_bytes = b"\\section{Initial v1}\n";
        let staged_v2 = b"\\section{Staged v2 Delete Conflict}\n";
        fs::write(&staged_abs, staged_v2).unwrap();
        let j = CommitJournal {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            tx_id: "delconflict".to_string(),
            project_id: pid.clone(),
            target_rel_path: "latex/main.tex".to_string(),
            base_revision: 1,
            target_revision: 2,
            before_hash: Some(sha256_hex(v1_bytes)),
            after_hash: sha256_hex(staged_v2),
            after_size_bytes: staged_v2.len() as u64,
            actor: "cli_user".to_string(),
            op_event_id: "op-del-conflict".to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            staged_temp_rel_path: staged_rel.to_string(),
            audit_id: Some("aud-del-conflict".to_string()),
            phase: CommitPhase::Audited,
            conflict_reason: None,
        };
        fs::write(&journal_path, serde_json::to_string_pretty(&j).unwrap()).unwrap();

        fs::remove_file(&main_abs).unwrap();

        let rep = ws.recover_workspace().unwrap();
        assert_eq!(rep.conflicted_journals, 1);
        assert_eq!(rep.rolled_forward_journals, 0);
        assert!(!main_abs.exists());
        assert!(staged_abs.exists());
        let saved_j: CommitJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        assert_eq!(saved_j.phase, CommitPhase::Conflicted);
    }

    // 4. Clean crash right after Audited mark (before target write: disk == before_hash, rev == base_revision)
    {
        let (_tmp, ws, pid) = setup_basic_workspace();
        let p_dir = ws.project_dir(&pid).unwrap();
        let main_abs = p_dir.join("latex/main.tex");
        let ops_path = p_dir.join("history/operations.jsonl");
        let journal_path = p_dir.join("history/.commit_journal.json");
        let staged_rel = "history/.ls-stage-cleanroll.tmp";
        let staged_abs = p_dir.join(staged_rel);

        let v1_bytes = b"\\section{Initial v1}\n";
        let staged_v2 = b"\\section{Clean Roll Forward v2}\n";
        fs::write(&staged_abs, staged_v2).unwrap();
        let j = CommitJournal {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            tx_id: "cleanroll".to_string(),
            project_id: pid.clone(),
            target_rel_path: "latex/main.tex".to_string(),
            base_revision: 1,
            target_revision: 2,
            before_hash: Some(sha256_hex(v1_bytes)),
            after_hash: sha256_hex(staged_v2),
            after_size_bytes: staged_v2.len() as u64,
            actor: "cli_user".to_string(),
            op_event_id: "op-clean-roll".to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            staged_temp_rel_path: staged_rel.to_string(),
            audit_id: Some("aud-clean-roll".to_string()),
            phase: CommitPhase::Audited,
            conflict_reason: None,
        };
        fs::write(&journal_path, serde_json::to_string_pretty(&j).unwrap()).unwrap();

        let rep = ws.recover_workspace().unwrap();
        assert_eq!(rep.conflicted_journals, 0);
        assert_eq!(rep.rolled_forward_journals, 1);
        assert_eq!(rep.removed_orphan_temps, 1);
        assert_eq!(fs::read(&main_abs).unwrap(), staged_v2);
        assert_eq!(ws.load_project(&pid).unwrap().revision, 2);
        assert!(!staged_abs.exists());
        assert!(!journal_path.exists());
        let ops = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
        assert!(ops.iter().any(|op| op.event_id == "op-clean-roll"));
    }
}
