//! Disposable SQLite FTS5 derived search/metadata index rebuilt cleanly from canonical files.

use std::fs;
use std::path::{Path, PathBuf};

use lecture_studio_history::{
    read_jsonl_strict, DecisionRecord, OperationRecord, SnapshotManifest, CANONICAL_CONTENT_DIRS,
};
use rusqlite::{params, Connection, OpenFlags};
use uuid::Uuid;

use crate::errors::WorkspaceError;
use crate::models::{IndexRebuildStats, ProjectConfig, SourceRecord};
use crate::path_guard::ensure_no_symlink_in_path;

#[derive(Debug, Clone)]
pub struct WorkspaceSqliteIndex {
    db_path: PathBuf,
}

impl WorkspaceSqliteIndex {
    #[must_use]
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Check SQLite integrity and presence of core derived tables.
    pub fn verify_integrity(&self) -> Result<bool, WorkspaceError> {
        if !self.db_path.exists() {
            return Ok(false);
        }
        let Ok(conn) = Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        else {
            return Ok(false);
        };
        let quick: Result<String, _> = conn.query_row("PRAGMA quick_check", [], |row| row.get(0));
        if !matches!(quick, Ok(ref s) if s == "ok") {
            return Ok(false);
        }
        let table_count: Result<i64, _> = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('projects','sources','operations','decisions','snapshots','files_fts')",
            [],
            |row| row.get(0),
        );
        Ok(matches!(table_count, Ok(6)))
    }

    /// Rebuild the entire SQLite index from canonical workspace files and replace atomically.
    pub fn rebuild_from_canonical(
        &self,
        ws_root: &Path,
    ) -> Result<IndexRebuildStats, WorkspaceError> {
        let cache_dir = self
            .db_path
            .parent()
            .ok_or_else(|| WorkspaceError::new("INVALID_INDEX_PATH", "no parent dir"))?;
        fs::create_dir_all(cache_dir)
            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;

        let tmp_db = cache_dir.join(format!(".workspace_index.{}.sqlite.tmp", Uuid::new_v4()));
        let mut stats = IndexRebuildStats {
            projects_indexed: 0,
            sources_indexed: 0,
            operations_indexed: 0,
            decisions_indexed: 0,
            snapshots_indexed: 0,
            files_indexed: 0,
        };

        {
            let mut conn = Connection::open(&tmp_db)
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
            conn.execute_batch(
                "
                PRAGMA journal_mode = DELETE;
                PRAGMA synchronous = FULL;
                CREATE TABLE projects (
                    project_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    revision INTEGER NOT NULL
                );
                CREATE TABLE sources (
                    source_id TEXT PRIMARY KEY,
                    origin_ref TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    classification TEXT NOT NULL
                );
                CREATE TABLE operations (
                    event_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    origin_type TEXT NOT NULL,
                    new_revision INTEGER NOT NULL
                );
                CREATE TABLE decisions (
                    decision_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    outcome TEXT NOT NULL
                );
                CREATE TABLE snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    creation_status TEXT NOT NULL
                );
                CREATE VIRTUAL TABLE files_fts USING fts5(
                    project_id UNINDEXED,
                    rel_path,
                    content,
                    tokenize='trigram'
                );
                ",
            )
            .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;

            let tx = conn
                .transaction()
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;

            // Index canonical sources
            let sources_jsonl = ws_root.join("sources").join("index.jsonl");
            for s in read_jsonl_strict::<SourceRecord>(&sources_jsonl)? {
                tx.execute(
                    "INSERT OR REPLACE INTO sources (source_id, origin_ref, sha256, classification) VALUES (?1, ?2, ?3, ?4)",
                    params![s.source_id, s.origin_ref, s.sha256, s.classification.as_str()],
                )
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                stats.sources_indexed += 1;
            }

            // Index all projects and their canonical history + files
            let projects_dir = ws_root.join("projects");
            if projects_dir.exists() {
                for entry in fs::read_dir(&projects_dir)
                    .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
                {
                    let entry =
                        entry.map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                    let p_dir = entry.path();
                    if !p_dir.is_dir() {
                        continue;
                    }
                    let proj_yaml = p_dir.join("project.yaml");
                    if !proj_yaml.exists() {
                        continue;
                    }
                    let raw = fs::read_to_string(&proj_yaml)
                        .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                    let proj: ProjectConfig = serde_yaml::from_str(&raw)
                        .map_err(|e| WorkspaceError::new("PROJECT_CORRUPT", e.to_string()))?;
                    let mode_s = match proj.mode {
                        crate::models::ProjectMode::LatexFirst => "latex_first",
                        crate::models::ProjectMode::TypstFirst => "typst_first",
                    };
                    tx.execute(
                        "INSERT OR REPLACE INTO projects (project_id, title, mode, classification, revision) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![proj.project_id, proj.title, mode_s, proj.classification.as_str(), proj.revision as i64],
                    )
                    .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                    stats.projects_indexed += 1;

                    let ops_path = p_dir.join("history").join("operations.jsonl");
                    for op in read_jsonl_strict::<OperationRecord>(&ops_path)? {
                        tx.execute(
                            "INSERT OR REPLACE INTO operations (event_id, project_id, actor, target_path, origin_type, new_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                op.event_id,
                                proj.project_id,
                                op.actor,
                                op.target_path,
                                format!("{:?}", op.origin_type).to_ascii_lowercase(),
                                op.new_revision as i64
                            ],
                        )
                        .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                        stats.operations_indexed += 1;
                    }

                    let decs_path = p_dir.join("history").join("decisions.jsonl");
                    for dec in read_jsonl_strict::<DecisionRecord>(&decs_path)? {
                        tx.execute(
                            "INSERT OR REPLACE INTO decisions (decision_id, project_id, proposal_id, outcome) VALUES (?1, ?2, ?3, ?4)",
                            params![
                                dec.decision_id,
                                proj.project_id,
                                dec.proposal_id,
                                format!("{:?}", dec.outcome).to_ascii_lowercase()
                            ],
                        )
                        .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                        stats.decisions_indexed += 1;
                    }

                    let snaps_dir = p_dir.join("history").join("snapshots");
                    if snaps_dir.exists() {
                        for se in fs::read_dir(&snaps_dir)
                            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
                        {
                            let se =
                                se.map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                            let sp = se.path();
                            if sp.extension().and_then(|e| e.to_str()) != Some("json") {
                                continue;
                            }
                            let sraw = fs::read_to_string(&sp)
                                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                            let snap: SnapshotManifest =
                                serde_json::from_str(&sraw).map_err(|e| {
                                    WorkspaceError::new("SNAPSHOT_CORRUPT", e.to_string())
                                })?;
                            tx.execute(
                                "INSERT OR REPLACE INTO snapshots (snapshot_id, project_id, revision, creation_status) VALUES (?1, ?2, ?3, ?4)",
                                params![
                                    snap.snapshot_id,
                                    proj.project_id,
                                    snap.revision as i64,
                                    format!("{:?}", snap.creation_status).to_ascii_lowercase()
                                ],
                            )
                            .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                            stats.snapshots_indexed += 1;
                        }
                    }

                    for sub in CANONICAL_CONTENT_DIRS {
                        let sub_dir = p_dir.join(sub);
                        if !sub_dir.is_dir() {
                            continue;
                        }
                        let mut stack = vec![sub_dir];
                        while let Some(d) = stack.pop() {
                            for fe in fs::read_dir(&d)
                                .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
                            {
                                let fe =
                                    fe.map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?;
                                let fp = fe.path();
                                ensure_no_symlink_in_path(&fp)?;
                                if fp.is_dir() {
                                    stack.push(fp);
                                } else if fp.is_file() {
                                    let rel = fp
                                        .strip_prefix(&p_dir)
                                        .unwrap_or(&fp)
                                        .to_string_lossy()
                                        .replace('\\', "/");
                                    let bytes = fs::read(&fp).map_err(|e| {
                                        WorkspaceError::new("IO_ERROR", e.to_string())
                                    })?;
                                    let text = String::from_utf8_lossy(&bytes).into_owned();
                                    tx.execute(
                                        "INSERT INTO files_fts (project_id, rel_path, content) VALUES (?1, ?2, ?3)",
                                        params![proj.project_id, rel, text],
                                    )
                                    .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
                                    stats.files_indexed += 1;
                                }
                            }
                        }
                    }
                }
            }

            tx.commit()
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
        }

        if self.db_path.exists() {
            let _ = fs::remove_file(&self.db_path);
        }
        fs::rename(&tmp_db, &self.db_path).map_err(|e| {
            let _ = fs::remove_file(&tmp_db);
            WorkspaceError::new("INDEX_REPLACE_FAILED", e.to_string())
        })?;
        Ok(stats)
    }

    pub fn search_files(&self, query: &str) -> Result<Vec<(String, String)>, WorkspaceError> {
        if !self.verify_integrity()? {
            return Err(WorkspaceError::new(
                "INDEX_CORRUPTED",
                "SQLite derived index is missing or corrupted; rebuild required.",
            ));
        }
        let conn = Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;

        let mut results = Vec::new();
        if query.chars().count() >= 3 {
            let fts_query = format!("\"{}\"", query.replace('"', "\"\""));
            let mut stmt = conn
                .prepare("SELECT project_id, rel_path FROM files_fts WHERE files_fts MATCH ?1 ORDER BY project_id, rel_path")
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
            let rows = stmt
                .query_map(params![fts_query], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
            for r in rows {
                results.push(r.map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?);
            }
        } else {
            let like_pat = format!("%{query}%");
            let mut stmt = conn
                .prepare("SELECT project_id, rel_path FROM files_fts WHERE content LIKE ?1 OR rel_path LIKE ?1 ORDER BY project_id, rel_path")
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
            let rows = stmt
                .query_map(params![like_pat], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
            for r in rows {
                results.push(r.map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?);
            }
        }
        Ok(results)
    }

    pub fn count_table_rows(&self, table: &str) -> Result<usize, WorkspaceError> {
        let sql = match table {
            "projects" => "SELECT COUNT(*) FROM projects",
            "sources" => "SELECT COUNT(*) FROM sources",
            "operations" => "SELECT COUNT(*) FROM operations",
            "decisions" => "SELECT COUNT(*) FROM decisions",
            "snapshots" => "SELECT COUNT(*) FROM snapshots",
            _ => {
                return Err(WorkspaceError::new(
                    "INVALID_TABLE",
                    format!("unsupported index table: {table}"),
                ))
            }
        };
        let conn = Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
        let count: i64 = conn
            .query_row(sql, [], |r| r.get(0))
            .map_err(|e| WorkspaceError::new("INDEX_ERROR", e.to_string()))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }
}
