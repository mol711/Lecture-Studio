# Lecture-Studio

Local-first, security-isolated authoring environment for university lectures and academic documents (Apache-2.0).

## Setup

```powershell
# Python worker/test environment (uv)
uv sync

# Rust core & CLI workspace
cargo build --workspace
```

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
uv run ruff check .
uv run pytest -v
```

## CLI (Dual Switchable Sandbox Backends)

```powershell
cargo run -p lecture-studio-cli -- backends
cargo run -p lecture-studio-cli -- run-dummy --sandbox wsl-linux-bwrap --input <input.json> --output <output.json> --audit-log <audit.jsonl>
cargo run -p lecture-studio-cli -- run-dummy --sandbox auto --input <input.json> --output <output.json> --audit-log <audit.jsonl>
# Windows native backend fails closed before worker launch unless staging resides on a bounded volume (see LECTURE_STUDIO_WINDOWS_STAGING_VOLUME)
cargo run -p lecture-studio-cli -- run-dummy --sandbox windows-appcontainer --input <input.json> --output <output.json> --audit-log <audit.jsonl>
```
