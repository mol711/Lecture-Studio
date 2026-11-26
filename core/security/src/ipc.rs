//! POC-02 JSON-RPC 2.0 framing, strict limits, allowlists, and actor binding.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::errors::SecurityError;
use crate::models::Actor;

pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
pub const MAX_JSON_DEPTH: usize = 32;
pub const ALLOWED_RPC_METHODS: &[&str] = &[
    "job.submit",
    "job.cancel",
    "job.status",
    "sandbox.list_backends",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcEnvelope {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Map<String, Value>,
}

fn check_json_depth(val: &Value, depth: usize) -> Result<(), SecurityError> {
    if depth > MAX_JSON_DEPTH {
        return Err(SecurityError::IpcParse {
            user_message: "IPC payload exceeds maximum JSON nesting depth.".to_string(),
            detail: format!("max_depth={MAX_JSON_DEPTH}"),
        });
    }
    match val {
        Value::Array(items) => {
            for item in items {
                check_json_depth(item, depth + 1)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                check_json_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn encode_content_length_frame(envelope: &IpcEnvelope) -> Result<Vec<u8>, SecurityError> {
    let body = serde_json::to_vec(envelope).map_err(|e| SecurityError::IpcParse {
        user_message: "Failed to serialize IPC envelope.".to_string(),
        detail: e.to_string(),
    })?;
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(SecurityError::IpcParse {
            user_message: "Encoded IPC message exceeds 4 MiB limit.".to_string(),
            detail: format!("size={}", body.len()),
        });
    }
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let mut out = header.into_bytes();
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_content_length_frame(raw_frame: &[u8]) -> Result<IpcEnvelope, SecurityError> {
    let sep = b"\r\n\r\n";
    let Some(pos) = raw_frame.windows(sep.len()).position(|w| w == sep) else {
        return Err(SecurityError::IpcParse {
            user_message: "Missing Content-Length header terminator.".to_string(),
            detail: String::new(),
        });
    };
    let header_bytes = &raw_frame[..pos];
    let body = &raw_frame[pos + sep.len()..];

    let header_str = std::str::from_utf8(header_bytes).map_err(|e| SecurityError::IpcParse {
        user_message: "Non-UTF-8 IPC frame header.".to_string(),
        detail: e.to_string(),
    })?;

    let mut content_length: Option<usize> = None;
    for line in header_str.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                let parsed = v
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| SecurityError::IpcParse {
                        user_message: "Invalid Content-Length value.".to_string(),
                        detail: v.trim().to_string(),
                    })?;
                content_length = Some(parsed);
                break;
            }
        }
    }

    let declared = content_length.ok_or_else(|| SecurityError::IpcParse {
        user_message: "Missing Content-Length header.".to_string(),
        detail: String::new(),
    })?;

    if declared > MAX_MESSAGE_BYTES || body.len() > MAX_MESSAGE_BYTES {
        return Err(SecurityError::IpcParse {
            user_message: "IPC message exceeds maximum allowed byte size (4 MiB).".to_string(),
            detail: format!("declared={declared} actual={}", body.len()),
        });
    }
    if body.len() != declared {
        return Err(SecurityError::IpcParse {
            user_message: "IPC frame length mismatch.".to_string(),
            detail: format!("declared={declared} actual={}", body.len()),
        });
    }

    parse_and_validate_json_bytes(body)
}

pub fn decode_ndjson_line(raw_line: &[u8]) -> Result<IpcEnvelope, SecurityError> {
    if raw_line.len() > MAX_MESSAGE_BYTES {
        return Err(SecurityError::IpcParse {
            user_message: "NDJSON message exceeds 4 MiB limit.".to_string(),
            detail: format!("size={}", raw_line.len()),
        });
    }
    let trimmed = raw_line
        .strip_suffix(b"\n")
        .unwrap_or(raw_line)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| raw_line.strip_suffix(b"\n").unwrap_or(raw_line));
    parse_and_validate_json_bytes(trimmed)
}

fn parse_and_validate_json_bytes(body: &[u8]) -> Result<IpcEnvelope, SecurityError> {
    let text = std::str::from_utf8(body).map_err(|e| SecurityError::IpcParse {
        user_message: "IPC payload is not valid UTF-8.".to_string(),
        detail: e.to_string(),
    })?;
    let val: Value = serde_json::from_str(text).map_err(|e| SecurityError::IpcParse {
        user_message: "Malformed JSON in IPC payload.".to_string(),
        detail: e.to_string(),
    })?;
    check_json_depth(&val, 1)?;

    let obj = val
        .as_object()
        .ok_or_else(|| SecurityError::InvalidRequest {
            user_message: "JSON-RPC payload must be a JSON object.".to_string(),
            detail: String::new(),
        })?;

    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        if !ALLOWED_RPC_METHODS.contains(&method) {
            return Err(SecurityError::OperationNotAllowed {
                user_message: "Requested JSON-RPC method is not in the allowlist.".to_string(),
                detail: format!("method={method}"),
            });
        }
    }

    let env: IpcEnvelope =
        serde_json::from_value(val).map_err(|e| SecurityError::InvalidRequest {
            user_message: "IPC request failed envelope schema validation.".to_string(),
            detail: e.to_string(),
        })?;

    if env.jsonrpc != "2.0" {
        return Err(SecurityError::InvalidRequest {
            user_message: "Unsupported JSON-RPC version (expected 2.0).".to_string(),
            detail: env.jsonrpc,
        });
    }
    if !(env.id.is_string() || env.id.is_number()) {
        return Err(SecurityError::InvalidRequest {
            user_message: "JSON-RPC id must be a string or number.".to_string(),
            detail: String::new(),
        });
    }
    Ok(env)
}

pub fn verify_channel_actor(
    envelope: &IpcEnvelope,
    trusted_actor: Actor,
) -> Result<(), SecurityError> {
    for key in ["actor", "claimed_actor"] {
        if let Some(val) = envelope.params.get(key) {
            let Some(s) = val.as_str() else {
                return Err(SecurityError::InvalidParams {
                    user_message: "Actor parameter must be a string.".to_string(),
                    detail: key.to_string(),
                });
            };
            if s != trusted_actor.as_str() {
                return Err(SecurityError::PolicyDenied {
                    code: "ACTOR_SPOOF",
                    user_message: "Self-reported actor does not match trusted connection identity."
                        .to_string(),
                    detail: format!("key={key} value={s} trusted={}", trusted_actor.as_str()),
                });
            }
        }
    }
    Ok(())
}
