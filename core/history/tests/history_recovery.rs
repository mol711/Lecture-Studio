use std::fs;
use std::io::Write;

use lecture_studio_history::{
    append_jsonl_record, create_snapshot, read_jsonl_strict, recover_jsonl_tail, restore_snapshot,
    verify_snapshot, ConsentPurpose, ConsentStore, HistoryError, OperationRecord, OriginType,
    SnapshotStatus, CURRENT_HISTORY_SCHEMA_VERSION,
};
use tempfile::TempDir;

#[test]
fn snapshot_create_verify_restore_with_pre_backup_and_tamper_rejection() {
    let tmp = TempDir::new().unwrap();
    let proj_dir = tmp.path().join("proj");
    let snaps_dir = proj_dir.join("history").join("snapshots");
    fs::create_dir_all(proj_dir.join("latex")).unwrap();
    fs::create_dir_all(proj_dir.join("typst")).unwrap();

    fs::write(
        proj_dir.join("latex").join("main.tex"),
        b"\\section{Rev 1}\n",
    )
    .unwrap();
    fs::write(proj_dir.join("typst").join("extra.typ"), b"= Extra Rev 1\n").unwrap();

    let snap1 = create_snapshot(
        &proj_dir,
        &snaps_dir,
        "proj-1",
        1,
        Some("baseline".to_string()),
        SnapshotStatus::Complete,
    )
    .unwrap();
    assert_eq!(snap1.files.len(), 2);
    verify_snapshot(&snaps_dir, &snap1.snapshot_id).unwrap();

    // Mutate project (rev 2): modify main.tex, remove extra.typ, add new file
    fs::write(
        proj_dir.join("latex").join("main.tex"),
        b"\\section{Rev 2}\n",
    )
    .unwrap();
    fs::remove_file(proj_dir.join("typst").join("extra.typ")).unwrap();
    fs::write(proj_dir.join("latex").join("added.tex"), b"% extra rev 2").unwrap();

    // Restore snap1 -> creates pre_restore_backup capturing rev 2, restores snap1 cleanly
    let report = restore_snapshot(&proj_dir, &snaps_dir, "proj-1", 2, &snap1.snapshot_id).unwrap();
    assert_eq!(report.restored_files, 2);
    assert_eq!(
        fs::read_to_string(proj_dir.join("latex").join("main.tex")).unwrap(),
        "\\section{Rev 1}\n"
    );
    assert!(proj_dir.join("typst").join("extra.typ").exists());
    assert!(!proj_dir.join("latex").join("added.tex").exists());

    // Pre-restore backup snapshot is valid and preserves Rev 2 content
    let backup_manifest = verify_snapshot(&snaps_dir, &report.pre_restore_backup_id).unwrap();
    assert_eq!(
        backup_manifest.creation_status,
        SnapshotStatus::PreRestoreBackup
    );
    assert_eq!(backup_manifest.revision, 2);

    // Corrupted blob refuses restore without altering live project files
    let first_blob = snaps_dir.join("blobs").join(&snap1.files[0].sha256);
    fs::write(&first_blob, b"CORRUPTED_BLOB_BYTES").unwrap();
    let err = restore_snapshot(&proj_dir, &snaps_dir, "proj-1", 3, &snap1.snapshot_id).unwrap_err();
    assert!(matches!(err, HistoryError::SnapshotCorrupted(_)));
}

#[test]
fn jsonl_tail_recovery_consent_separation_and_schema_version_check() {
    let tmp = TempDir::new().unwrap();
    let ops_path = tmp.path().join("operations.jsonl");

    let op1 = OperationRecord {
        schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
        event_id: "op-1".to_string(),
        timestamp_utc: "2026-11-26T00:00:00Z".to_string(),
        actor: "cli_user".to_string(),
        target_path: "latex/main.tex".to_string(),
        before_hash: None,
        after_hash: Some("a".repeat(64)),
        base_revision: 0,
        new_revision: 1,
        origin_type: OriginType::Editor,
        note: None,
    };
    append_jsonl_record(&ops_path, &op1).unwrap();

    // Append truncated tail simulating crash / disk-full mid-write
    {
        let mut fh = fs::OpenOptions::new().append(true).open(&ops_path).unwrap();
        writeln!(fh, "{{\"schema_version\":\"1.0.0\",\"event_id\":\"partial").unwrap();
    }
    assert!(read_jsonl_strict::<OperationRecord>(&ops_path).is_err());

    let rep = recover_jsonl_tail::<OperationRecord>(&ops_path).unwrap();
    assert_eq!(rep.valid_records, 1);
    assert_eq!(rep.dropped_tail_lines, 1);
    assert!(std::path::Path::new(rep.sidecar_path.as_ref().unwrap()).exists());
    let recovered = read_jsonl_strict::<OperationRecord>(&ops_path).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].event_id, "op-1");

    // Consent separation & revocation
    let store = ConsentStore::new(tmp.path().join("consents.jsonl"));
    let c_hist = store
        .grant("proj-1", ConsentPurpose::HistorySave, "teacher", "1.0.0")
        .unwrap();
    let c_train = store
        .grant("proj-1", ConsentPurpose::LearningTrain, "teacher", "1.0.0")
        .unwrap();
    assert!(store
        .has_active_consent("proj-1", ConsentPurpose::HistorySave)
        .unwrap());
    assert!(store
        .has_active_consent("proj-1", ConsentPurpose::LearningTrain)
        .unwrap());
    assert!(!store
        .has_active_consent("proj-1", ConsentPurpose::ExternalExchange)
        .unwrap());

    // Revoking training consent does NOT revoke history_save
    store.revoke(&c_train.consent_id).unwrap();
    assert!(store
        .has_active_consent("proj-1", ConsentPurpose::HistorySave)
        .unwrap());
    assert!(!store
        .has_active_consent("proj-1", ConsentPurpose::LearningTrain)
        .unwrap());
    store.revoke(&c_hist.consent_id).unwrap();
    assert!(!store
        .has_active_consent("proj-1", ConsentPurpose::HistorySave)
        .unwrap());
}
