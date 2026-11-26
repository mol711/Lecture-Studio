//! CLI entrypoint using the shared Rust SecurityGateway with switchable sandboxes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use lecture_studio_security::sandbox::list_backend_availability;
use lecture_studio_security::{
    Actor, DataClassification, HashChainedAuditLog, JobExecutionContext, JobRequest, JobStatus,
    Operation, PolicyEngine, Purpose, ResourceLimits, SandboxMode, SecurityGateway,
};
use lecture_studio_workspace::{ProjectMode, WorkspaceManager};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSandboxMode {
    Auto,
    LinuxBwrap,
    WindowsAppcontainer,
    WslLinuxBwrap,
}

impl From<CliSandboxMode> for SandboxMode {
    fn from(m: CliSandboxMode) -> Self {
        match m {
            CliSandboxMode::Auto => Self::Auto,
            CliSandboxMode::LinuxBwrap => Self::LinuxBwrap,
            CliSandboxMode::WindowsAppcontainer => Self::WindowsAppcontainer,
            CliSandboxMode::WslLinuxBwrap => Self::WslLinuxBwrap,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "lecture-studio-cli",
    about = "Lecture-Studio Phase 1 Security CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect available OS isolation backends.
    Backends {
        #[arg(long, default_value = "Ubuntu")]
        wsl_distro: String,
    },
    /// Execute the synthetic dummy worker via SecurityGateway with explicit sandbox selection.
    RunDummy {
        #[arg(long, value_enum, default_value_t = CliSandboxMode::Auto)]
        sandbox: CliSandboxMode,
        #[arg(long, default_value = "Ubuntu")]
        wsl_distro: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        audit_log: PathBuf,
        #[arg(long)]
        quarantine_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        revision: u64,
    },
    /// Manage Phase 2 workspaces, durable projects, snapshots, recovery, and exchange tasks.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceCommands,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliProjectMode {
    LatexFirst,
    TypstFirst,
}

impl From<CliProjectMode> for ProjectMode {
    fn from(m: CliProjectMode) -> Self {
        match m {
            CliProjectMode::LatexFirst => Self::LatexFirst,
            CliProjectMode::TypstFirst => Self::TypstFirst,
        }
    }
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommands {
    Init {
        #[arg(long)]
        root: PathBuf,
        #[arg(long = "allow-input", required = true)]
        allow_inputs: Vec<PathBuf>,
        #[arg(long = "allow-output", required = true)]
        allow_outputs: Vec<PathBuf>,
    },
    CreateProject {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, value_enum, default_value_t = CliProjectMode::LatexFirst)]
        mode: CliProjectMode,
        #[arg(long, default_value = "latex/main.tex")]
        entry: String,
        #[arg(long)]
        content_file: PathBuf,
    },
    Save {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        rel_path: String,
        #[arg(long)]
        content_file: PathBuf,
        #[arg(long)]
        expected_revision: u64,
    },
    Snapshot {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Restore {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        snapshot_id: String,
    },
    Recover {
        #[arg(long)]
        root: PathBuf,
    },
    IngestExchange {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        task_file: PathBuf,
    },
}

fn find_dummy_worker_script() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let worker = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|r| r.join("runtime").join("dummy_worker").join("worker.py"))
        .ok_or_else(|| "Unable to resolve repository root".to_string())?;
    if !worker.exists() {
        return Err(format!("Missing worker script: {}", worker.display()));
    }
    Ok(worker)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Backends { wsl_distro } => {
            let avail = list_backend_availability(&wsl_distro);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "available_backends": avail }))
                    .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Commands::RunDummy {
            sandbox,
            wsl_distro,
            input,
            output,
            audit_log,
            quarantine_dir,
            revision,
        } => {
            let Ok(worker_script) = find_dummy_worker_script() else {
                eprintln!("Failed locating runtime/dummy_worker/worker.py");
                return ExitCode::from(2);
            };
            let Ok(raw_in) = fs::read(&input) else {
                eprintln!("Failed reading input file: {}", input.display());
                return ExitCode::from(2);
            };
            let mut hasher = Sha256::new();
            hasher.update(&raw_in);
            let input_hash = hex::encode(hasher.finalize());

            let job_id = format!("job-{}", &Uuid::new_v4().simple().to_string()[..12]);
            let req_id = format!("req-{}", &Uuid::new_v4().simple().to_string()[..12]);
            let input_name = input
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("input.json")
                .to_string();

            let Ok(tmp) = TempDir::with_prefix("ls_cli_") else {
                eprintln!("Failed creating temporary job directory");
                return ExitCode::from(2);
            };
            let in_dir = tmp.path().join("in");
            let st_dir = tmp.path().join("staging");
            if fs::create_dir_all(&in_dir).is_err() || fs::create_dir_all(&st_dir).is_err() {
                eprintln!("Failed initializing temporary directories");
                return ExitCode::from(2);
            }
            if fs::write(in_dir.join(&input_name), &raw_in).is_err() {
                eprintln!("Failed copying input into job input directory");
                return ExitCode::from(2);
            }

            let abs_out = if output.is_absolute() {
                output
            } else {
                std::env::current_dir().unwrap_or_default().join(output)
            };
            let q_dir = quarantine_dir.unwrap_or_else(|| {
                abs_out
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("quarantine")
            });

            let req = JobRequest {
                schema_version: "1.0.0".to_string(),
                request_id: req_id,
                job_id: job_id.clone(),
                actor: Actor::CliUser,
                claimed_actor: Actor::CliUser,
                project_id: "cli-project".to_string(),
                operation: Operation::DummyEcho,
                purpose: Purpose::SecurityVerification,
                policy_version: "1.0.0".to_string(),
                input_revision: revision,
                input_hash,
                classification: DataClassification::Public,
                allowed_inputs: vec![input_name.clone()],
                staging_output_ref: "out.json".to_string(),
                resource_limits: ResourceLimits::default(),
            };

            let mut gw = SecurityGateway::new(
                PolicyEngine::default(),
                HashChainedAuditLog::new(audit_log, true),
                sandbox.into(),
                wsl_distro,
                true,
            );
            let worker_args = vec![
                "--mode".to_string(),
                "benign".to_string(),
                "--input".to_string(),
                format!("{{INPUT_DIR}}/{input_name}"),
                "--output".to_string(),
                "{STAGING_DIR}/out.json".to_string(),
                "--job-id".to_string(),
                job_id,
                "--revision".to_string(),
                revision.to_string(),
            ];

            match gw.execute_dummy_job(
                &req,
                &JobExecutionContext {
                    trusted_channel_actor: Actor::CliUser,
                    current_revision: revision,
                    input_dir: &in_dir,
                    staging_dir: &st_dir,
                    official_output_file: &abs_out,
                    quarantine_dir: &q_dir,
                    worker_script: &worker_script,
                    worker_args: &worker_args,
                },
            ) {
                Ok(resp) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&resp).unwrap_or_default()
                    );
                    if resp.status == JobStatus::Committed {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::Workspace { action } => run_workspace_command(action),
    }
}

fn run_workspace_command(action: WorkspaceCommands) -> ExitCode {
    match action {
        WorkspaceCommands::Init {
            root,
            allow_inputs,
            allow_outputs,
        } => match WorkspaceManager::init_workspace(root, allow_inputs, allow_outputs) {
            Ok(ws) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(ws.config()).unwrap_or_default()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        },
        WorkspaceCommands::CreateProject {
            root,
            title,
            mode,
            entry,
            content_file,
        } => {
            let Ok(bytes) = fs::read(&content_file) else {
                eprintln!("Failed reading content file: {}", content_file.display());
                return ExitCode::from(2);
            };
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.create_project(
                title,
                mode.into(),
                &entry,
                &bytes,
                DataClassification::Internal,
                "cli_user",
            ) {
                Ok(proj) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&proj).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        WorkspaceCommands::Save {
            root,
            project_id,
            rel_path,
            content_file,
            expected_revision,
        } => {
            let Ok(bytes) = fs::read(&content_file) else {
                eprintln!("Failed reading content file: {}", content_file.display());
                return ExitCode::from(2);
            };
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.save_project_file(
                &project_id,
                &rel_path,
                &bytes,
                expected_revision,
                None,
                "cli_user",
            ) {
                Ok(proj) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&proj).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        WorkspaceCommands::Snapshot {
            root,
            project_id,
            reason,
        } => {
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.create_project_snapshot(&project_id, reason, "cli_user") {
                Ok(snap) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snap).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        WorkspaceCommands::Restore {
            root,
            project_id,
            snapshot_id,
        } => {
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.restore_project_snapshot(&project_id, &snapshot_id, "cli_user") {
                Ok((proj, report)) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &json!({ "project": proj, "restore": report })
                        )
                        .unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        WorkspaceCommands::Recover { root } => {
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.recover_workspace() {
                Ok(rep) => {
                    println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        WorkspaceCommands::IngestExchange { root, task_file } => {
            let ws = match WorkspaceManager::open_workspace(root) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            match ws.ingest_exchange_task(&task_file) {
                Ok(task) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&task).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
