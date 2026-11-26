use std::fs;
use std::io::Write;

use chrono::{Duration, Utc};
use lecture_studio_history::{
    ConsentPurpose, DecisionOutcome, SnapshotManifest, SnapshotStatus,
    CURRENT_HISTORY_SCHEMA_VERSION,
};
use lecture_studio_security::DataClassification;
use lecture_studio_workspace::{
    ExchangeTask, ExchangeTaskStatus, ExternalChangeKind, ProjectLockGuard, ProjectMode,
    SourcePermissions, WorkspaceManager, WorkspaceSqliteIndex, CURRENT_WORKSPACE_SCHEMA_VERSION,
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

    // Simulate crash-truncated JSONL tails and orphan temp file
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
    fs::write(ws_root.join("projects").join(".orphan.tmp"), b"temp").unwrap();

    let rec = ws_reopened.recover_workspace().unwrap();
    assert_eq!(rec.project_history_dropped_lines, 1);
    assert_eq!(rec.removed_orphan_temps, 1);
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
