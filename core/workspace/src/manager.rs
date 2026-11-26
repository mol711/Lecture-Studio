//! WorkspaceManager: durable canonical files, optimistic revision locking, external diff & exchange gateway, and crash recovery.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use lecture_studio_history::{
    append_jsonl_record, create_snapshot, read_jsonl_strict, recover_jsonl_tail, restore_snapshot,
    ConsentStore, DecisionOutcome, DecisionRecord, OperationRecord, OriginType, RestoreReport,
    SnapshotManifest, SnapshotStatus, CANONICAL_CONTENT_DIRS, CURRENT_HISTORY_SCHEMA_VERSION,
};
use lecture_studio_security::audit::AuditAppendInput;
use lecture_studio_security::staging::{atomic_promote, to_long_path};
use lecture_studio_security::{AuditDecision, DataClassification, HashChainedAuditLog};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::WorkspaceError;
use crate::lock::ProjectLockGuard;
use crate::models::{
    CommitJournal, CommitPhase, ExchangeTask, ExchangeTaskStatus, ExternalChangeKind,
    ExternalChangeReport, ExternalFileChange, FileFingerprint, ProcessedExchangeKey, ProjectConfig,
    ProjectMode, RecoveryReport, RetentionPolicy, SourcePermissions, SourceRecord, WorkspaceConfig,
    CURRENT_WORKSPACE_SCHEMA_VERSION,
};
use crate::path_guard::{
    ensure_no_symlink_in_path, resolve_without_symlinks, validate_relative_path,
    verify_path_within_allowed_roots,
};
use crate::sqlite_index::WorkspaceSqliteIndex;

const WORKSPACE_SUBDIRS: &[&str] = &[
    "sources/originals",
    "sources/extracted",
    "projects",
    "knowledge_base",
    "learning/feedback",
    "learning/datasets",
    "learning/experiments",
    "learning/evaluations",
    "models/base",
    "models/adapters",
    "models/merged",
    "models/quantized",
    "tasks",
    "exchange/inbox",
    "exchange/outbox",
    "exchange/proposals",
    "security/policies",
    "security/audit",
    "security/quarantine",
    "backups",
    "cache",
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn ensure_canonical_content_rel_path(rel_path: &str) -> Result<(String, PathBuf), WorkspaceError> {
    let pb = validate_relative_path(rel_path)?;
    let normalized = pb.to_string_lossy().replace('\\', "/");
    let first = normalized.split('/').next().unwrap_or("");
    if !CANONICAL_CONTENT_DIRS.contains(&first) {
        return Err(WorkspaceError::new(
            "PATH_ESCAPE",
            format!(
                "target path must reside under one of {:?}: {rel_path}",
                CANONICAL_CONTENT_DIRS
            ),
        ));
    }
    Ok((normalized, pb))
}

fn validate_id_segment(id: &str, code: &'static str) -> Result<(), WorkspaceError> {
    if id.is_empty()
        || id.contains("..")
        || id.contains('/')
        || id.contains('\\')
        || id.contains(':')
        || id.chars().any(char::is_control)
    {
        return Err(WorkspaceError::new(
            code,
            format!("invalid identifier: {id}"),
        ));
    }
    Ok(())
}

pub struct WorkspaceManager {
    root: PathBuf,
    config: WorkspaceConfig,
    audit_log: HashChainedAuditLog,
    consent_store: ConsentStore,
    index: WorkspaceSqliteIndex,
}

impl WorkspaceManager {
    pub fn init_workspace(
        root: impl AsRef<Path>,
        allowed_input_roots: Vec<PathBuf>,
        allowed_output_roots: Vec<PathBuf>,
    ) -> Result<Self, WorkspaceError> {
        let root_pb = root.as_ref().to_path_buf();
        fs::create_dir_all(to_long_path(&root_pb))
            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        ensure_no_symlink_in_path(&root_pb)?;
        for sub in WORKSPACE_SUBDIRS {
            fs::create_dir_all(to_long_path(&root_pb.join(sub)))
                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        }

        if allowed_input_roots.is_empty() || allowed_output_roots.is_empty() {
            return Err(WorkspaceError::new(
                "INVALID_PARAMS",
                "allowed_input_roots and allowed_output_roots must be non-empty.",
            ));
        }

        let mut norm_in = Vec::with_capacity(allowed_input_roots.len());
        for p in &allowed_input_roots {
            ensure_no_symlink_in_path(p)?;
            let canon = fs::canonicalize(p)
                .map_err(|e| WorkspaceError::new("PATH_RESOLUTION_FAILED", e.to_string()))?;
            norm_in.push(canon.to_string_lossy().into_owned());
        }
        let mut norm_out = Vec::with_capacity(allowed_output_roots.len());
        for p in &allowed_output_roots {
            fs::create_dir_all(p).map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
            ensure_no_symlink_in_path(p)?;
            let canon = fs::canonicalize(p)
                .map_err(|e| WorkspaceError::new("PATH_RESOLUTION_FAILED", e.to_string()))?;
            norm_out.push(canon.to_string_lossy().into_owned());
        }

        let config = WorkspaceConfig {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            workspace_id: format!("ws-{}", Uuid::new_v4().simple()),
            created_at_utc: Utc::now().to_rfc3339(),
            allowed_input_roots: norm_in,
            allowed_output_roots: norm_out,
            retention_policy: Some(RetentionPolicy {
                max_snapshot_count: None,
                retention_days: None,
            }),
        };
        let yaml = serde_yaml::to_string(&config)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(yaml.as_bytes(), &root_pb.join("workspace.yaml"))?;

        let audit_log = HashChainedAuditLog::new(
            root_pb.join("security").join("audit").join("audit.jsonl"),
            true,
        );
        let consent_store = ConsentStore::new(
            root_pb
                .join("security")
                .join("policies")
                .join("consents.jsonl"),
        );
        let index = WorkspaceSqliteIndex::new(root_pb.join("cache").join("workspace_index.sqlite"));
        index.rebuild_from_canonical(&root_pb)?;

        Ok(Self {
            root: root_pb,
            config,
            audit_log,
            consent_store,
            index,
        })
    }

    pub fn open_workspace(root: impl AsRef<Path>) -> Result<Self, WorkspaceError> {
        let root_pb = root.as_ref().to_path_buf();
        ensure_no_symlink_in_path(&root_pb)?;
        let ws_yaml = root_pb.join("workspace.yaml");
        let raw = fs::read_to_string(&ws_yaml).map_err(|e| {
            WorkspaceError::new("WORKSPACE_NOT_FOUND", format!("{}: {e}", ws_yaml.display()))
        })?;
        let config: WorkspaceConfig = serde_yaml::from_str(&raw)
            .map_err(|e| WorkspaceError::new("WORKSPACE_CORRUPT", e.to_string()))?;
        if config.schema_version != CURRENT_WORKSPACE_SCHEMA_VERSION {
            return Err(WorkspaceError::new(
                "SCHEMA_VERSION_INCOMPATIBLE",
                format!(
                    "expected workspace schema_version={}, got {}",
                    CURRENT_WORKSPACE_SCHEMA_VERSION, config.schema_version
                ),
            ));
        }

        let audit_log = HashChainedAuditLog::new(
            root_pb.join("security").join("audit").join("audit.jsonl"),
            true,
        );
        let consent_store = ConsentStore::new(
            root_pb
                .join("security")
                .join("policies")
                .join("consents.jsonl"),
        );
        let index = WorkspaceSqliteIndex::new(root_pb.join("cache").join("workspace_index.sqlite"));

        Ok(Self {
            root: root_pb,
            config,
            audit_log,
            consent_store,
            index,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    #[must_use]
    pub fn consent_store(&self) -> &ConsentStore {
        &self.consent_store
    }

    #[must_use]
    pub fn audit_log(&self) -> &HashChainedAuditLog {
        &self.audit_log
    }

    #[must_use]
    pub fn sqlite_index(&self) -> &WorkspaceSqliteIndex {
        &self.index
    }

    pub fn project_dir(&self, project_id: &str) -> Result<PathBuf, WorkspaceError> {
        validate_id_segment(project_id, "INVALID_PROJECT_ID")?;
        Ok(self.root.join("projects").join(project_id))
    }

    pub fn load_project(&self, project_id: &str) -> Result<ProjectConfig, WorkspaceError> {
        let p_dir = self.project_dir(project_id)?;
        let p_yaml = to_long_path(&p_dir.join("project.yaml"));
        let raw = fs::read_to_string(&p_yaml).map_err(|e| {
            WorkspaceError::new("PROJECT_NOT_FOUND", format!("{}: {e}", p_yaml.display()))
        })?;
        let proj: ProjectConfig = serde_yaml::from_str(&raw)
            .map_err(|e| WorkspaceError::new("PROJECT_CORRUPT", e.to_string()))?;
        if proj.schema_version != CURRENT_WORKSPACE_SCHEMA_VERSION {
            return Err(WorkspaceError::new(
                "SCHEMA_VERSION_INCOMPATIBLE",
                format!(
                    "expected project schema_version={}, got {}",
                    CURRENT_WORKSPACE_SCHEMA_VERSION, proj.schema_version
                ),
            ));
        }
        Ok(proj)
    }

    fn save_project_config(&self, project: &ProjectConfig) -> Result<(), WorkspaceError> {
        let p_dir = self.project_dir(&project.project_id)?;
        let yaml = serde_yaml::to_string(project)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(yaml.as_bytes(), &p_dir.join("project.yaml"))?;
        Ok(())
    }

    fn append_audit(&self, input: AuditAppendInput<'_>) -> Result<String, WorkspaceError> {
        let rec = self.audit_log.append(input)?;
        Ok(rec.audit_id)
    }

    fn allowed_input_paths(&self) -> Vec<PathBuf> {
        self.config
            .allowed_input_roots
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    fn allowed_output_paths(&self) -> Vec<PathBuf> {
        self.config
            .allowed_output_roots
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    pub fn create_project(
        &self,
        title: impl Into<String>,
        mode: ProjectMode,
        canonical_entry: &str,
        initial_content: &[u8],
        classification: DataClassification,
        actor: &str,
    ) -> Result<ProjectConfig, WorkspaceError> {
        let (norm_entry, entry_pb) = ensure_canonical_content_rel_path(canonical_entry)?;
        let project_id = format!("proj-{}", Uuid::new_v4().simple());
        let p_dir = self.project_dir(&project_id)?;
        let digest = sha256_hex(initial_content);

        // Mandatory audit BEFORE creating canonical project directories/files (fail-closed)
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_create_project",
            purpose: "edit_preview",
            project_id: &project_id,
            job_id: &project_id,
            policy_version: "1.0.0",
            classification,
            input_hash: &digest,
            output_hash: Some(&digest),
            decision: AuditDecision::Allow,
            reason_code: "PROJECT_CREATED",
            error_code: None,
            extra_keys: &[],
        })?;

        for sub in [
            "latex",
            "typst",
            "assets",
            "code",
            "pdf",
            "mappings",
            "proposals",
            "history/snapshots/blobs",
        ] {
            fs::create_dir_all(to_long_path(&p_dir.join(sub)))
                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        }

        let entry_abs = p_dir.join(entry_pb);
        atomic_promote(initial_content, &entry_abs)?;
        let now = Utc::now().to_rfc3339();
        let mut tracked_files = BTreeMap::new();
        tracked_files.insert(
            norm_entry.clone(),
            FileFingerprint {
                sha256: digest.clone(),
                size_bytes: initial_content.len() as u64,
            },
        );

        let project = ProjectConfig {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            project_id: project_id.clone(),
            title: title.into(),
            mode,
            canonical_entry: norm_entry.clone(),
            compiler_profile: match mode {
                ProjectMode::LatexFirst => "lualatex_default".to_string(),
                ProjectMode::TypstFirst => "typst_default".to_string(),
            },
            classification,
            revision: 1,
            tracked_files,
            created_at_utc: now.clone(),
            updated_at_utc: now.clone(),
        };
        self.save_project_config(&project)?;

        let op = OperationRecord {
            schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            event_id: format!("op-{}", Uuid::new_v4().simple()),
            timestamp_utc: now,
            actor: actor.to_string(),
            target_path: norm_entry,
            before_hash: None,
            after_hash: Some(digest),
            base_revision: 0,
            new_revision: 1,
            origin_type: OriginType::System,
            note: Some("project_initialized".to_string()),
        };
        append_jsonl_record(&p_dir.join("history").join("operations.jsonl"), &op)?;
        create_snapshot(
            &p_dir,
            &p_dir.join("history").join("snapshots"),
            &project_id,
            1,
            Some("initial_project_state".to_string()),
            SnapshotStatus::Complete,
        )?;
        self.index.rebuild_from_canonical(&self.root)?;
        Ok(project)
    }

    pub fn import_source(
        &self,
        external_path: &Path,
        page_or_line_range: impl Into<String>,
        permissions: SourcePermissions,
        classification: DataClassification,
        actor: &str,
    ) -> Result<SourceRecord, WorkspaceError> {
        let verified_src = verify_path_within_allowed_roots(
            external_path,
            &self.allowed_input_paths(),
            "PATH_OUTSIDE_ALLOWED_ROOT",
        )?;
        if !verified_src.is_file() {
            return Err(WorkspaceError::new(
                "SOURCE_NOT_FILE",
                format!("source must be a regular file: {}", verified_src.display()),
            ));
        }

        let raw =
            fs::read(&verified_src).map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        let digest = sha256_hex(&raw);
        let source_id = format!("src-{}", Uuid::new_v4().simple());
        let file_name = verified_src
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source.bin");
        let stored_rel = format!("sources/originals/{source_id}_{file_name}");
        let stored_abs = self.root.join(&stored_rel);

        // Mandatory audit BEFORE promoting source copy or modifying sources/index.jsonl
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_import_source",
            purpose: "edit_preview",
            project_id: "workspace",
            job_id: &source_id,
            policy_version: "1.0.0",
            classification,
            input_hash: &digest,
            output_hash: Some(&digest),
            decision: AuditDecision::Allow,
            reason_code: "SOURCE_IMPORTED",
            error_code: None,
            extra_keys: &[],
        })?;

        atomic_promote(&raw, &stored_abs)?;
        let record = SourceRecord {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            source_id,
            origin_ref: verified_src.to_string_lossy().into_owned(),
            stored_rel_path: stored_rel,
            sha256: digest,
            size_bytes: raw.len() as u64,
            original_revision: 1,
            page_or_line_range: page_or_line_range.into(),
            usage_permission: permissions.usage,
            learning_permission: permissions.learning,
            export_permission: permissions.export,
            classification,
            imported_at_utc: Utc::now().to_rfc3339(),
        };
        append_jsonl_record(&self.root.join("sources").join("index.jsonl"), &record)?;
        self.index.rebuild_from_canonical(&self.root)?;
        Ok(record)
    }

    pub fn export_project_file(
        &self,
        project_id: &str,
        rel_path: &str,
        destination: &Path,
        actor: &str,
    ) -> Result<PathBuf, WorkspaceError> {
        let project = self.load_project(project_id)?;
        let (norm_rel, rel_pb) = ensure_canonical_content_rel_path(rel_path)?;
        let p_dir = self.project_dir(project_id)?;
        let src_abs = p_dir.join(rel_pb);
        ensure_no_symlink_in_path(&src_abs)?;
        let bytes = fs::read(to_long_path(&src_abs))
            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        let digest = sha256_hex(&bytes);

        let verified_dest = verify_path_within_allowed_roots(
            destination,
            &self.allowed_output_paths(),
            "PATH_OUTSIDE_ALLOWED_ROOT",
        )?;

        // Mandatory audit BEFORE writing exported destination file
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_export_file",
            purpose: "export_zip",
            project_id,
            job_id: &norm_rel,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: &digest,
            output_hash: Some(&digest),
            decision: AuditDecision::Allow,
            reason_code: "FILE_EXPORTED",
            error_code: None,
            extra_keys: &[],
        })?;
        atomic_promote(&bytes, &verified_dest)?;
        Ok(verified_dest)
    }

    pub fn save_project_file(
        &self,
        project_id: &str,
        rel_path: &str,
        new_content: &[u8],
        expected_revision: u64,
        expected_base_hash: Option<&str>,
        actor: &str,
    ) -> Result<ProjectConfig, WorkspaceError> {
        let (norm_rel, rel_pb) = ensure_canonical_content_rel_path(rel_path)?;
        let p_dir = self.project_dir(project_id)?;
        let _lock = ProjectLockGuard::acquire(&p_dir)?;

        let journal_path = p_dir.join("history").join(".commit_journal.json");
        let ext_journal = to_long_path(&journal_path);
        if ext_journal.exists() {
            if let Ok(raw) = fs::read_to_string(&ext_journal) {
                if let Ok(j) = serde_json::from_str::<CommitJournal>(&raw) {
                    if j.phase == CommitPhase::Conflicted {
                        return Err(WorkspaceError::new(
                            "RECOVERY_CONFLICT",
                            format!(
                                "Commit recovery conflict held for this project ({}); resolve preserved external/staged data before saving.",
                                j.conflict_reason.as_deref().unwrap_or("state diverged")
                            ),
                        ));
                    }
                }
            }
            return Err(WorkspaceError::new(
                "RECOVERY_REQUIRED",
                "Unfinished commit journal detected; run recover_workspace before saving.",
            ));
        }

        let mut project = self.load_project(project_id)?;
        if project.revision != expected_revision {
            return Err(WorkspaceError::new(
                "REVISION_CONFLICT",
                format!(
                    "expected revision {expected_revision}, current revision is {}",
                    project.revision
                ),
            ));
        }

        let target_abs = p_dir.join(&rel_pb);
        ensure_no_symlink_in_path(&target_abs)?;
        let resolved_target = resolve_without_symlinks(&target_abs)?;
        let canon_proj = fs::canonicalize(&p_dir)
            .map_err(|e| WorkspaceError::new("PATH_RESOLUTION_FAILED", e.to_string()))?;
        if !resolved_target.starts_with(&canon_proj) {
            return Err(WorkspaceError::new(
                "PATH_ESCAPE",
                "target path resolved outside project directory.",
            ));
        }

        let tracked_hash = project
            .tracked_files
            .get(&norm_rel)
            .map(|f| f.sha256.clone());
        let ext_target = to_long_path(&target_abs);
        let before_hash = if ext_target.exists() {
            let cur_bytes = fs::read(&ext_target)
                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
            let disk_hash = sha256_hex(&cur_bytes);
            if tracked_hash.as_deref() != Some(disk_hash.as_str()) {
                return Err(WorkspaceError::new(
                    "EXTERNAL_MODIFICATION_DETECTED",
                    format!(
                        "external on-disk modification detected on {norm_rel}; refusing overwrite"
                    ),
                ));
            }
            if let Some(exp) = expected_base_hash {
                if exp != disk_hash {
                    return Err(WorkspaceError::new(
                        "REVISION_CONFLICT",
                        format!("base hash mismatch on {norm_rel}"),
                    ));
                }
            }
            Some(disk_hash)
        } else {
            if tracked_hash.is_some() {
                return Err(WorkspaceError::new(
                    "EXTERNAL_MODIFICATION_DETECTED",
                    format!("tracked file was externally deleted: {norm_rel}"),
                ));
            }
            None
        };

        let new_hash = sha256_hex(new_content);
        let base_rev = project.revision;
        let target_rev = base_rev.saturating_add(1);
        let now = Utc::now().to_rfc3339();
        let tx_id = format!("tx-{}", Uuid::new_v4().simple());
        let op_event_id = format!("op-{}", Uuid::new_v4().simple());
        let staged_rel = format!("history/.ls-stage-{tx_id}.tmp");
        let staged_abs = p_dir.join(&staged_rel);

        // Stage 2 (Prepared): stage payload & commit journal without modifying canonical files
        atomic_promote(new_content, &staged_abs)?;
        let mut journal = CommitJournal {
            schema_version: CURRENT_WORKSPACE_SCHEMA_VERSION.to_string(),
            tx_id,
            project_id: project_id.to_string(),
            target_rel_path: norm_rel.clone(),
            base_revision: base_rev,
            target_revision: target_rev,
            before_hash: before_hash.clone(),
            after_hash: new_hash.clone(),
            after_size_bytes: new_content.len() as u64,
            actor: actor.to_string(),
            op_event_id: op_event_id.clone(),
            timestamp_utc: now.clone(),
            staged_temp_rel_path: staged_rel,
            audit_id: None,
            phase: CommitPhase::Prepared,
            conflict_reason: None,
        };
        let j_bytes = serde_json::to_vec_pretty(&journal)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(&j_bytes, &journal_path)?;

        // Stage 3 (Mandatory Audit BEFORE canonical commit): abort cleanly if audit fails
        let audit_id = match self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_save_file",
            purpose: "edit_preview",
            project_id,
            job_id: &op_event_id,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: before_hash.as_deref().unwrap_or(&new_hash),
            output_hash: Some(&new_hash),
            decision: AuditDecision::Allow,
            reason_code: "FILE_SAVED",
            error_code: None,
            extra_keys: &[],
        }) {
            Ok(id) => id,
            Err(e) => {
                let _ = fs::remove_file(to_long_path(&staged_abs));
                let _ = fs::remove_file(to_long_path(&journal_path));
                return Err(e);
            }
        };

        // Stage 4 (Audited commit point)
        journal.phase = CommitPhase::Audited;
        journal.audit_id = Some(audit_id);
        let j_audited = serde_json::to_vec_pretty(&journal)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(&j_audited, &journal_path)?;

        // Stage 5 (Apply canonical state idempotently)
        atomic_promote(new_content, &target_abs)?;
        project.revision = target_rev;
        project.updated_at_utc = now.clone();
        project.tracked_files.insert(
            norm_rel.clone(),
            FileFingerprint {
                sha256: new_hash.clone(),
                size_bytes: new_content.len() as u64,
            },
        );
        self.save_project_config(&project)?;

        let op = OperationRecord {
            schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            event_id: op_event_id,
            timestamp_utc: now,
            actor: actor.to_string(),
            target_path: norm_rel,
            before_hash,
            after_hash: Some(new_hash),
            base_revision: base_rev,
            new_revision: target_rev,
            origin_type: OriginType::Editor,
            note: None,
        };
        append_jsonl_record(&p_dir.join("history").join("operations.jsonl"), &op)?;

        // Stage 6 (Finalize): remove staged file + commit journal, rebuild SQLite derived index
        let _ = fs::remove_file(to_long_path(&staged_abs));
        let _ = fs::remove_file(to_long_path(&journal_path));
        self.index.rebuild_from_canonical(&self.root)?;
        Ok(project)
    }

    pub fn detect_external_changes(
        &self,
        project_id: &str,
    ) -> Result<Vec<ExternalFileChange>, WorkspaceError> {
        let project = self.load_project(project_id)?;
        let p_dir = self.project_dir(project_id)?;

        let mut disk_state: BTreeMap<String, (String, u64)> = BTreeMap::new();
        for sub in CANONICAL_CONTENT_DIRS {
            let sub_dir = p_dir.join(sub);
            if !sub_dir.exists() {
                continue;
            }
            ensure_no_symlink_in_path(&sub_dir)?;
            let mut stack = vec![sub_dir];
            while let Some(d) = stack.pop() {
                for entry in
                    fs::read_dir(&d).map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
                {
                    let entry =
                        entry.map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                    let fp = entry.path();
                    ensure_no_symlink_in_path(&fp)?;
                    if fp.is_dir() {
                        stack.push(fp);
                    } else if fp.is_file() {
                        let rel = fp
                            .strip_prefix(&p_dir)
                            .unwrap_or(&fp)
                            .to_string_lossy()
                            .replace('\\', "/");
                        let raw = fs::read(&fp)
                            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                        disk_state.insert(rel, (sha256_hex(&raw), raw.len() as u64));
                    }
                }
            }
        }

        let mut all_paths: HashSet<String> = project.tracked_files.keys().cloned().collect();
        all_paths.extend(disk_state.keys().cloned());
        let mut sorted: Vec<String> = all_paths.into_iter().collect();
        sorted.sort();

        let mut changes = Vec::new();
        for rel in sorted {
            match (project.tracked_files.get(&rel), disk_state.get(&rel)) {
                (None, Some((after_h, _))) => changes.push(ExternalFileChange {
                    rel_path: rel,
                    kind: ExternalChangeKind::Added,
                    before_hash: None,
                    after_hash: Some(after_h.clone()),
                }),
                (Some(before_fp), None) => changes.push(ExternalFileChange {
                    rel_path: rel,
                    kind: ExternalChangeKind::Deleted,
                    before_hash: Some(before_fp.sha256.clone()),
                    after_hash: None,
                }),
                (Some(before_fp), Some((after_h, _))) if &before_fp.sha256 != after_h => {
                    changes.push(ExternalFileChange {
                        rel_path: rel,
                        kind: ExternalChangeKind::Modified,
                        before_hash: Some(before_fp.sha256.clone()),
                        after_hash: Some(after_h.clone()),
                    });
                }
                _ => {}
            }
        }
        Ok(changes)
    }

    pub fn import_external_changes(
        &self,
        project_id: &str,
        actor: &str,
    ) -> Result<ExternalChangeReport, WorkspaceError> {
        let changes = self.detect_external_changes(project_id)?;
        let p_dir = self.project_dir(project_id)?;
        let _lock = ProjectLockGuard::acquire(&p_dir)?;
        let mut project = self.load_project(project_id)?;

        if changes.is_empty() {
            return Ok(ExternalChangeReport {
                project_id: project_id.to_string(),
                observed_changes: Vec::new(),
                new_revision: project.revision,
                snapshot_id: None,
            });
        }

        let base_rev = project.revision;
        let new_rev = base_rev.saturating_add(1);
        let now = Utc::now().to_rfc3339();
        let agg_hash = sha256_hex(
            serde_json::to_string(&changes)
                .unwrap_or_default()
                .as_bytes(),
        );

        // Mandatory audit BEFORE modifying project config, history, or snapshot
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_import_external_diff",
            purpose: "edit_preview",
            project_id,
            job_id: &agg_hash,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: &agg_hash,
            output_hash: Some(&agg_hash),
            decision: AuditDecision::Allow,
            reason_code: "EXTERNAL_CHANGE_IMPORTED",
            error_code: None,
            extra_keys: &[],
        })?;

        project.revision = new_rev;
        project.updated_at_utc = now.clone();
        for ch in &changes {
            match &ch.after_hash {
                Some(h) => {
                    let abs = p_dir.join(&ch.rel_path);
                    let len = fs::metadata(to_long_path(&abs))
                        .map(|m| m.len())
                        .unwrap_or(0);
                    project.tracked_files.insert(
                        ch.rel_path.clone(),
                        FileFingerprint {
                            sha256: h.clone(),
                            size_bytes: len,
                        },
                    );
                }
                None => {
                    project.tracked_files.remove(&ch.rel_path);
                }
            }
            let op = OperationRecord {
                schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
                event_id: format!("op-{}", Uuid::new_v4().simple()),
                timestamp_utc: now.clone(),
                actor: actor.to_string(),
                target_path: ch.rel_path.clone(),
                before_hash: ch.before_hash.clone(),
                after_hash: ch.after_hash.clone(),
                base_revision: base_rev,
                new_revision: new_rev,
                origin_type: OriginType::ExternalDiff,
                note: Some(
                    "observed_external_hash_diff_only;unobserved_edits_and_reasons_not_fabricated"
                        .to_string(),
                ),
            };
            append_jsonl_record(&p_dir.join("history").join("operations.jsonl"), &op)?;
        }

        self.save_project_config(&project)?;
        let snap = create_snapshot(
            &p_dir,
            &p_dir.join("history").join("snapshots"),
            project_id,
            project.revision,
            Some("external_diff_imported".to_string()),
            SnapshotStatus::Complete,
        )?;
        self.index.rebuild_from_canonical(&self.root)?;

        Ok(ExternalChangeReport {
            project_id: project_id.to_string(),
            observed_changes: changes,
            new_revision: project.revision,
            snapshot_id: Some(snap.snapshot_id),
        })
    }

    pub fn create_project_snapshot(
        &self,
        project_id: &str,
        reason: Option<String>,
        actor: &str,
    ) -> Result<SnapshotManifest, WorkspaceError> {
        let p_dir = self.project_dir(project_id)?;
        let _lock = ProjectLockGuard::acquire(&p_dir)?;
        let project = self.load_project(project_id)?;
        let rev_hash = sha256_hex(format!("{project_id}:{}", project.revision).as_bytes());
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_create_snapshot",
            purpose: "edit_preview",
            project_id,
            job_id: &project.project_id,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: &rev_hash,
            output_hash: Some(&rev_hash),
            decision: AuditDecision::Allow,
            reason_code: "SNAPSHOT_CREATED",
            error_code: None,
            extra_keys: &[],
        })?;
        let snap = create_snapshot(
            &p_dir,
            &p_dir.join("history").join("snapshots"),
            project_id,
            project.revision,
            reason,
            SnapshotStatus::Complete,
        )?;
        self.index.rebuild_from_canonical(&self.root)?;
        Ok(snap)
    }

    pub fn restore_project_snapshot(
        &self,
        project_id: &str,
        snapshot_id: &str,
        actor: &str,
    ) -> Result<(ProjectConfig, RestoreReport), WorkspaceError> {
        let p_dir = self.project_dir(project_id)?;
        let _lock = ProjectLockGuard::acquire(&p_dir)?;
        let mut project = self.load_project(project_id)?;
        let snaps_dir = p_dir.join("history").join("snapshots");

        // Verify target snapshot integrity and record mandatory audit BEFORE modifying canonical files
        let restored_manifest = lecture_studio_history::verify_snapshot(&snaps_dir, snapshot_id)?;
        let h = sha256_hex(snapshot_id.as_bytes());
        self.append_audit(AuditAppendInput {
            actor,
            operation: "workspace_restore_snapshot",
            purpose: "edit_preview",
            project_id,
            job_id: snapshot_id,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: &h,
            output_hash: Some(&h),
            decision: AuditDecision::Allow,
            reason_code: "SNAPSHOT_RESTORED",
            error_code: None,
            extra_keys: &[],
        })?;

        let report = restore_snapshot(
            &p_dir,
            &snaps_dir,
            project_id,
            project.revision,
            snapshot_id,
        )?;

        let base_rev = project.revision;
        project.revision = base_rev.saturating_add(1);
        let now = Utc::now().to_rfc3339();
        project.updated_at_utc = now.clone();
        project.tracked_files.clear();
        for f in &restored_manifest.files {
            project.tracked_files.insert(
                f.rel_path.clone(),
                FileFingerprint {
                    sha256: f.sha256.clone(),
                    size_bytes: f.size_bytes,
                },
            );
        }
        self.save_project_config(&project)?;

        let op = OperationRecord {
            schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            event_id: format!("op-{}", Uuid::new_v4().simple()),
            timestamp_utc: now,
            actor: actor.to_string(),
            target_path: project.canonical_entry.clone(),
            before_hash: None,
            after_hash: project
                .tracked_files
                .get(&project.canonical_entry)
                .map(|f| f.sha256.clone()),
            base_revision: base_rev,
            new_revision: project.revision,
            origin_type: OriginType::System,
            note: Some(format!(
                "restored_snapshot:{snapshot_id};pre_restore_backup:{}",
                report.pre_restore_backup_id
            )),
        };
        append_jsonl_record(&p_dir.join("history").join("operations.jsonl"), &op)?;
        self.index.rebuild_from_canonical(&self.root)?;
        Ok((project, report))
    }

    pub fn ingest_exchange_task(
        &self,
        task_file_path: &Path,
    ) -> Result<ExchangeTask, WorkspaceError> {
        let inbox = self.root.join("exchange").join("inbox");
        let verified_task_path = verify_path_within_allowed_roots(
            task_file_path,
            &[inbox],
            "EXCHANGE_BOUNDARY_VIOLATION",
        )?;
        if !verified_task_path.is_file() {
            return Err(WorkspaceError::new(
                "EXCHANGE_BOUNDARY_VIOLATION",
                "exchange task path is not a regular file.",
            ));
        }

        let raw = fs::read_to_string(&verified_task_path)
            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
        let mut task: ExchangeTask = serde_json::from_str(&raw)
            .map_err(|e| WorkspaceError::new("INVALID_EXCHANGE_TASK", e.to_string()))?;
        if task.schema_version != CURRENT_WORKSPACE_SCHEMA_VERSION {
            return Err(WorkspaceError::new(
                "SCHEMA_VERSION_INCOMPATIBLE",
                format!("unsupported exchange task schema: {}", task.schema_version),
            ));
        }
        validate_id_segment(&task.task_id, "INVALID_TASK_ID")?;
        validate_id_segment(&task.project_id, "INVALID_PROJECT_ID")?;

        if task.actor != "external_agent" {
            let _ = self.append_audit(AuditAppendInput {
                actor: &task.actor,
                operation: "exchange_ingest_task",
                purpose: "ai_assist",
                project_id: &task.project_id,
                job_id: &task.task_id,
                policy_version: "1.0.0",
                classification: DataClassification::Internal,
                input_hash: &task.input_hash,
                output_hash: None,
                decision: AuditDecision::Deny,
                reason_code: "ACTOR_SPOOF",
                error_code: None,
                extra_keys: &[],
            });
            return Err(WorkspaceError::new(
                "ACTOR_SPOOF",
                "exchange tasks must carry actor=external_agent.",
            ));
        }
        if !matches!(
            task.allowed_operation.as_str(),
            "propose_edit" | "propose_patch"
        ) {
            return Err(WorkspaceError::new(
                "OPERATION_NOT_ALLOWED",
                format!("disallowed exchange operation: {}", task.allowed_operation),
            ));
        }

        let (norm_target, _) = ensure_canonical_content_rel_path(&task.target_rel_path)?;
        task.target_rel_path = norm_target;

        let expires = DateTime::parse_from_rfc3339(&task.expires_at_utc).map_err(|e| {
            WorkspaceError::new(
                "INVALID_EXCHANGE_TASK",
                format!("invalid expires_at_utc: {e}"),
            )
        })?;
        let task_record_path = self
            .root
            .join("tasks")
            .join(format!("{}.json", task.task_id));

        if expires.with_timezone(&Utc) < Utc::now() {
            task.status = ExchangeTaskStatus::Expired;
            let _ = atomic_promote(
                serde_json::to_string_pretty(&task)
                    .unwrap_or_default()
                    .as_bytes(),
                &task_record_path,
            );
            let _ = self.append_audit(AuditAppendInput {
                actor: "external_agent",
                operation: "exchange_ingest_task",
                purpose: "ai_assist",
                project_id: &task.project_id,
                job_id: &task.task_id,
                policy_version: "1.0.0",
                classification: DataClassification::Internal,
                input_hash: &task.input_hash,
                output_hash: None,
                decision: AuditDecision::Deny,
                reason_code: "TASK_EXPIRED",
                error_code: None,
                extra_keys: &[],
            });
            return Err(WorkspaceError::new(
                "TASK_EXPIRED",
                "exchange task expired.",
            ));
        }

        let keys_path = self.root.join("tasks").join("processed_keys.jsonl");
        let existing_keys = read_jsonl_strict::<ProcessedExchangeKey>(&keys_path)?;
        if existing_keys.iter().any(|k| {
            k.project_id == task.project_id
                && k.allowed_operation == task.allowed_operation
                && k.target_revision == task.target_revision
                && k.request_id == task.request_id
        }) {
            let _ = self.append_audit(AuditAppendInput {
                actor: "external_agent",
                operation: "exchange_ingest_task",
                purpose: "ai_assist",
                project_id: &task.project_id,
                job_id: &task.task_id,
                policy_version: "1.0.0",
                classification: DataClassification::Internal,
                input_hash: &task.input_hash,
                output_hash: None,
                decision: AuditDecision::Deny,
                reason_code: "DUPLICATE_TASK",
                error_code: None,
                extra_keys: &[],
            });
            return Err(WorkspaceError::new(
                "DUPLICATE_TASK",
                "duplicate exchange request_id rejected (idempotency).",
            ));
        }

        let project = self.load_project(&task.project_id)?;
        let current_hash = project
            .tracked_files
            .get(&task.target_rel_path)
            .map(|f| f.sha256.clone())
            .unwrap_or_default();
        if task.target_revision != project.revision || task.input_hash != current_hash {
            task.status = ExchangeTaskStatus::Conflicted;
            atomic_promote(
                serde_json::to_string_pretty(&task)
                    .unwrap_or_default()
                    .as_bytes(),
                &task_record_path,
            )?;
            let _ = self.append_audit(AuditAppendInput {
                actor: "external_agent",
                operation: "exchange_ingest_task",
                purpose: "ai_assist",
                project_id: &task.project_id,
                job_id: &task.task_id,
                policy_version: "1.0.0",
                classification: project.classification,
                input_hash: &task.input_hash,
                output_hash: None,
                decision: AuditDecision::Deny,
                reason_code: "REVISION_CONFLICT",
                error_code: None,
                extra_keys: &[],
            });
            return Err(WorkspaceError::new(
                "REVISION_CONFLICT",
                format!(
                    "exchange task target_revision={} / input_hash mismatch against current revision={}",
                    task.target_revision, project.revision
                ),
            ));
        }

        let prop_hash = sha256_hex(task.proposal_content.as_bytes());
        let audit_id = self.append_audit(AuditAppendInput {
            actor: "external_agent",
            operation: "exchange_ingest_task",
            purpose: "ai_assist",
            project_id: &task.project_id,
            job_id: &task.task_id,
            policy_version: "1.0.0",
            classification: project.classification,
            input_hash: &task.input_hash,
            output_hash: Some(&prop_hash),
            decision: AuditDecision::Proposed,
            reason_code: "EXCHANGE_PROPOSAL_STAGED",
            error_code: None,
            extra_keys: &[],
        })?;

        task.status = ExchangeTaskStatus::Proposed;
        task.output_hash = Some(prop_hash);
        task.audit_id = Some(audit_id);

        let serialized_task = serde_json::to_string_pretty(&task)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(serialized_task.as_bytes(), &task_record_path)?;
        atomic_promote(
            serialized_task.as_bytes(),
            &self
                .root
                .join("exchange")
                .join("proposals")
                .join(format!("{}.json", task.task_id)),
        )?;
        atomic_promote(
            serialized_task.as_bytes(),
            &self
                .project_dir(&task.project_id)?
                .join("proposals")
                .join(format!("{}.json", task.task_id)),
        )?;

        append_jsonl_record(
            &keys_path,
            &ProcessedExchangeKey {
                project_id: task.project_id.clone(),
                allowed_operation: task.allowed_operation.clone(),
                target_revision: task.target_revision,
                request_id: task.request_id.clone(),
                task_id: task.task_id.clone(),
            },
        )?;
        Ok(task)
    }

    pub fn apply_exchange_proposal(
        &self,
        project_id: &str,
        task_id: &str,
        outcome: DecisionOutcome,
        explicit_reason: Option<String>,
        edited_content: Option<&[u8]>,
        actor: &str,
    ) -> Result<ExchangeTask, WorkspaceError> {
        validate_id_segment(task_id, "INVALID_TASK_ID")?;
        let task_path = self.root.join("tasks").join(format!("{task_id}.json"));
        let raw = fs::read_to_string(&task_path).map_err(|e| {
            WorkspaceError::new("TASK_NOT_FOUND", format!("{}: {e}", task_path.display()))
        })?;
        let mut task: ExchangeTask = serde_json::from_str(&raw)
            .map_err(|e| WorkspaceError::new("INVALID_EXCHANGE_TASK", e.to_string()))?;
        if task.project_id != project_id {
            return Err(WorkspaceError::new(
                "INVALID_PARAMS",
                "task project_id mismatch.",
            ));
        }
        if task.status != ExchangeTaskStatus::Proposed {
            return Err(WorkspaceError::new(
                "DUPLICATE_TASK",
                "exchange proposal has already been finalized.",
            ));
        }

        let p_dir = self.project_dir(project_id)?;
        let dec = DecisionRecord {
            schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            decision_id: format!("dec-{}", Uuid::new_v4().simple()),
            timestamp_utc: Utc::now().to_rfc3339(),
            actor: actor.to_string(),
            proposal_id: task_id.to_string(),
            outcome,
            explicit_reason,
            inferred_reason: None,
            generation_context: "external_exchange".to_string(),
        };
        append_jsonl_record(&p_dir.join("history").join("decisions.jsonl"), &dec)?;

        match outcome {
            DecisionOutcome::Accepted | DecisionOutcome::Edited => {
                let bytes = match edited_content {
                    Some(b) => b,
                    None => task.proposal_content.as_bytes(),
                };
                self.save_project_file(
                    project_id,
                    &task.target_rel_path,
                    bytes,
                    task.target_revision,
                    Some(&task.input_hash),
                    actor,
                )?;
                task.status = ExchangeTaskStatus::Accepted;
            }
            DecisionOutcome::Rejected => {
                task.status = ExchangeTaskStatus::Rejected;
                self.index.rebuild_from_canonical(&self.root)?;
            }
            DecisionOutcome::Deferred => {
                self.index.rebuild_from_canonical(&self.root)?;
            }
        }

        let serialized = serde_json::to_string_pretty(&task)
            .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
        atomic_promote(serialized.as_bytes(), &task_path)?;
        Ok(task)
    }

    fn reconcile_project_commit_journal(
        &self,
        p_dir: &Path,
        project_id: &str,
        counters: &mut JournalRecoveryCounters,
    ) -> Result<(), WorkspaceError> {
        let journal_path = p_dir.join("history").join(".commit_journal.json");
        let ext_journal = to_long_path(&journal_path);
        if !ext_journal.exists() {
            return Ok(());
        }
        let raw = fs::read_to_string(&ext_journal)
            .map_err(|e| WorkspaceError::new("JOURNAL_READ_ERROR", e.to_string()))?;
        let mut journal: CommitJournal = serde_json::from_str(&raw)
            .map_err(|e| WorkspaceError::new("JOURNAL_CORRUPT", e.to_string()))?;
        if journal.project_id != project_id {
            return Err(WorkspaceError::new(
                "JOURNAL_CORRUPT",
                format!(
                    "commit journal project_id={} does not match directory {}",
                    journal.project_id, project_id
                ),
            ));
        }

        let staged_pb = validate_relative_path(&journal.staged_temp_rel_path)?;
        let staged_norm = staged_pb.to_string_lossy().replace('\\', "/");
        if !staged_norm.starts_with("history/.ls-stage-") {
            return Err(WorkspaceError::new(
                "JOURNAL_CORRUPT",
                format!(
                    "invalid app staged temp path: {}",
                    journal.staged_temp_rel_path
                ),
            ));
        }
        let staged_abs = p_dir.join(&staged_pb);
        ensure_no_symlink_in_path(&staged_abs)?;
        let ext_staged = to_long_path(&staged_abs);

        match journal.phase {
            CommitPhase::Prepared => {
                // Crashed before mandatory audit completed: roll back safely without modifying canonical files.
                if ext_staged.exists() && fs::remove_file(&ext_staged).is_ok() {
                    counters.removed_temps += 1;
                }
                fs::remove_file(&ext_journal)
                    .map_err(|e| WorkspaceError::new("JOURNAL_CLEANUP_FAILED", e.to_string()))?;
                counters.rolled_back += 1;
            }
            CommitPhase::Conflicted => {
                // Already quarantined as a conflict: preserve external disk state, staged payload, and journal idempotently.
                counters.conflicted += 1;
                counters.conflicted_projects.push(project_id.to_string());
            }
            CommitPhase::Audited => {
                // Inspect both project.yaml and current on-disk canonical file BEFORE mutating anything.
                let (norm_target, target_rel_pb) =
                    ensure_canonical_content_rel_path(&journal.target_rel_path)?;
                let target_abs = p_dir.join(&target_rel_pb);
                ensure_no_symlink_in_path(&target_abs)?;
                let ext_target = to_long_path(&target_abs);

                let mut project = self.load_project(project_id)?;
                let tracked_hash = project
                    .tracked_files
                    .get(&norm_target)
                    .map(|f| f.sha256.as_str());
                let current_disk_hash = match fs::read(&ext_target) {
                    Ok(bytes) => Some(sha256_hex(&bytes)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(WorkspaceError::new("IO_ERROR", e.to_string())),
                };

                let proj_is_base = project.revision == journal.base_revision
                    && tracked_hash == journal.before_hash.as_deref();
                let proj_is_target = project.revision == journal.target_revision
                    && tracked_hash == Some(journal.after_hash.as_str());
                let disk_is_before = current_disk_hash == journal.before_hash;
                let disk_is_after =
                    current_disk_hash.as_deref() == Some(journal.after_hash.as_str());

                let can_roll_forward = (proj_is_base && disk_is_before)
                    || (proj_is_base && disk_is_after)
                    || (proj_is_target && disk_is_after);

                if !can_roll_forward {
                    let mut reasons = Vec::new();
                    if !(proj_is_base || proj_is_target) {
                        reasons.push(format!(
                            "project state diverged (revision={}, expected {} or {}; tracked_hash={:?}, expected before={:?} or after={})",
                            project.revision,
                            journal.base_revision,
                            journal.target_revision,
                            tracked_hash,
                            journal.before_hash,
                            journal.after_hash,
                        ));
                    }
                    if !(disk_is_before || disk_is_after) {
                        reasons.push(format!(
                            "on-disk file {} modified or deleted externally (disk_hash={:?}, expected before={:?} or after={})",
                            norm_target,
                            current_disk_hash,
                            journal.before_hash,
                            journal.after_hash,
                        ));
                    }
                    if reasons.is_empty() {
                        reasons.push(format!(
                            "incompatible project/disk state (revision={}, disk_hash={:?})",
                            project.revision, current_disk_hash
                        ));
                    }
                    let reason = reasons.join("; ");

                    journal.phase = CommitPhase::Conflicted;
                    journal.conflict_reason = Some(reason);
                    let j_bytes = serde_json::to_vec_pretty(&journal)
                        .map_err(|e| WorkspaceError::new("SERIALIZE_ERROR", e.to_string()))?;
                    atomic_promote(&j_bytes, &journal_path)?;

                    self.append_audit(AuditAppendInput {
                        actor: "workspace_recovery",
                        operation: "workspace_recover_commit_journal",
                        purpose: "edit_preview",
                        project_id,
                        job_id: &journal.op_event_id,
                        policy_version: "1.0.0",
                        classification: project.classification,
                        input_hash: current_disk_hash.as_deref().unwrap_or(&journal.after_hash),
                        output_hash: Some(&journal.after_hash),
                        decision: AuditDecision::Deny,
                        reason_code: "RECOVERY_CONFLICT",
                        error_code: None,
                        extra_keys: &[],
                    })?;

                    counters.conflicted += 1;
                    counters.conflicted_projects.push(project_id.to_string());
                    return Ok(());
                }

                // Clean roll-forward path: current state matches known crash point without external conflict.
                if !disk_is_after {
                    let staged_bytes = fs::read(&ext_staged).map_err(|e| {
                        WorkspaceError::new(
                            "JOURNAL_RECOVERY_FAILED",
                            format!("missing staged payload for audited journal: {e}"),
                        )
                    })?;
                    if sha256_hex(&staged_bytes) != journal.after_hash {
                        return Err(WorkspaceError::new(
                            "JOURNAL_CORRUPT",
                            "staged payload hash mismatch during roll-forward recovery.",
                        ));
                    }
                    atomic_promote(&staged_bytes, &target_abs)?;
                }

                if proj_is_base {
                    project.revision = journal.target_revision;
                    project.updated_at_utc = journal.timestamp_utc.clone();
                    project.tracked_files.insert(
                        norm_target.clone(),
                        FileFingerprint {
                            sha256: journal.after_hash.clone(),
                            size_bytes: journal.after_size_bytes,
                        },
                    );
                    self.save_project_config(&project)?;
                }

                let ops_path = p_dir.join("history").join("operations.jsonl");
                let existing_ops = read_jsonl_strict::<OperationRecord>(&ops_path)?;
                if !existing_ops
                    .iter()
                    .any(|op| op.event_id == journal.op_event_id)
                {
                    let op = OperationRecord {
                        schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
                        event_id: journal.op_event_id.clone(),
                        timestamp_utc: journal.timestamp_utc.clone(),
                        actor: journal.actor.clone(),
                        target_path: norm_target,
                        before_hash: journal.before_hash.clone(),
                        after_hash: Some(journal.after_hash.clone()),
                        base_revision: journal.base_revision,
                        new_revision: journal.target_revision,
                        origin_type: OriginType::Editor,
                        note: Some("recovered_from_audited_commit_journal".to_string()),
                    };
                    append_jsonl_record(&ops_path, &op)?;
                }

                if ext_staged.exists() && fs::remove_file(&ext_staged).is_ok() {
                    counters.removed_temps += 1;
                }
                fs::remove_file(&ext_journal)
                    .map_err(|e| WorkspaceError::new("JOURNAL_CLEANUP_FAILED", e.to_string()))?;
                counters.rolled_forward += 1;
            }
        }
        Ok(())
    }

    pub fn recover_workspace(&self) -> Result<RecoveryReport, WorkspaceError> {
        let (_, audit_sidecar) = self.audit_log.recover_truncated_tail()?;
        let audit_dropped = usize::from(audit_sidecar.is_some());
        let consent_rep = self.consent_store.recover_corrupt_tail()?;
        let sources_rep =
            recover_jsonl_tail::<SourceRecord>(&self.root.join("sources").join("index.jsonl"))?;
        let keys_rep = recover_jsonl_tail::<ProcessedExchangeKey>(
            &self.root.join("tasks").join("processed_keys.jsonl"),
        )?;

        let mut proj_hist_dropped = 0usize;
        let mut j_counters = JournalRecoveryCounters::default();
        let mut skipped_locked_projects = 0usize;

        let projects_dir = self.root.join("projects");
        if projects_dir.exists() {
            for entry in fs::read_dir(&projects_dir)
                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
            {
                let entry = entry.map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                let p_dir = entry.path();
                if !p_dir.is_dir() {
                    continue;
                }
                let proj_id = entry.file_name().to_string_lossy().into_owned();
                let lock = match ProjectLockGuard::acquire(&p_dir) {
                    Ok(g) => g,
                    Err(e) if e.code() == "LOCK_CONTENTION" => {
                        skipped_locked_projects += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let op_rep = recover_jsonl_tail::<OperationRecord>(
                    &p_dir.join("history").join("operations.jsonl"),
                )?;
                let dec_rep = recover_jsonl_tail::<DecisionRecord>(
                    &p_dir.join("history").join("decisions.jsonl"),
                )?;
                proj_hist_dropped += op_rep.dropped_tail_lines + dec_rep.dropped_tail_lines;

                self.reconcile_project_commit_journal(&p_dir, &proj_id, &mut j_counters)?;
                drop(lock);
            }
        }

        j_counters.removed_temps += self.index.cleanup_recorded_index_temp()?;
        let need_rebuild = !self.index.verify_integrity()?;
        let stats = self.index.rebuild_from_canonical(&self.root)?;

        Ok(RecoveryReport {
            audit_dropped_lines: audit_dropped,
            consent_dropped_lines: consent_rep.dropped_tail_lines,
            sources_dropped_lines: sources_rep.dropped_tail_lines,
            exchange_keys_dropped_lines: keys_rep.dropped_tail_lines,
            project_history_dropped_lines: proj_hist_dropped,
            rolled_back_journals: j_counters.rolled_back,
            rolled_forward_journals: j_counters.rolled_forward,
            conflicted_journals: j_counters.conflicted,
            conflicted_projects: j_counters.conflicted_projects,
            skipped_locked_projects,
            removed_orphan_temps: j_counters.removed_temps,
            index_rebuilt: need_rebuild,
            index_stats: stats,
        })
    }
}

#[derive(Default)]
struct JournalRecoveryCounters {
    rolled_back: usize,
    rolled_forward: usize,
    conflicted: usize,
    conflicted_projects: Vec<String>,
    removed_temps: usize,
}
