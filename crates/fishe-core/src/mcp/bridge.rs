//! `fishe.exe --mcp-stdio`: an MCP stdio server for clients that can only
//! launch local servers over stdio. It forwards each JSON-RPC line from
//! stdin to the running Fishe's HTTP endpoint and writes the answer to
//! stdout. Port and token come from Fishe's `mcp.json`, read on every
//! message (a new token or port applies without restarting the client).
//!
//! No window opens; Fishe itself must be running with MCP enabled.

use crate::paths::Paths;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::time::Duration;

fn error(id: Value, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": message } })
}

/// Forward stdin to Fishe until stdin closes. Returns the exit code.
pub fn run() -> i32 {
    // No app handle here: resolve the data folder the same way `setup` does.
    let path = Paths::from_env_or_default().mcp_config();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        // wait_for_traffic may block up to 120 s.
        .timeout_global(Some(Duration::from_secs(150)))
        .build()
        .into();
    let mut session: Option<String> = None;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let id = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| v.get("id").cloned());
        let cfg: Option<super::McpConfig> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let replies: Vec<Value> = match cfg {
            None => id.into_iter().map(|id| {
                error(
                    id,
                    format!(
                        "Fishe's MCP settings were not found ({}): open Fishe → Settings → Agents and enable it",
                        path.display()
                    ),
                )
            }).collect(),
            Some(cfg) if !cfg.enabled => id.into_iter().map(|id| {
                error(id, "Fishe's MCP server is off: enable it in Fishe → Settings → Agents".into())
            }).collect(),
            Some(cfg) => {
                let url = format!("http://127.0.0.1:{}/mcp", cfg.port);
                let mut req = agent
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header("Authorization", &format!("Bearer {}", cfg.token));
                if let Some(s) = &session {
                    req = req.header("Mcp-Session-Id", s);
                }
                match req.send(line) {
                    Ok(mut resp) => {
                        if let Some(s) = resp
                            .headers()
                            .get("mcp-session-id")
                            .and_then(|v| v.to_str().ok())
                        {
                            session = Some(s.to_string());
                        }
                        let status = resp.status().as_u16();
                        let sse = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|t| t.starts_with("text/event-stream"));
                        let body = resp.body_mut().read_to_string().unwrap_or_default();
                        match status {
                            202 => Vec::new(),
                            200 if sse => sse_messages(&body),
                            200 => serde_json::from_str::<Value>(&body).ok().into_iter().collect(),
                            _ => id
                                .into_iter()
                                .map(|id| error(id, format!("Fishe answered HTTP {status}: {}", body.trim())))
                                .collect(),
                        }
                    }
                    Err(e) => id
                        .into_iter()
                        .map(|id| error(id, format!("Fishe is not running or not reachable on {url}: {e}")))
                        .collect(),
                }
            }
        };
        let written = replies.iter().all(|v| writeln!(out, "{v}").is_ok()) && out.flush().is_ok();
        if !written {
            break;
        }
    }
    0
}

/// JSON-RPC messages in a server-sent-events body (the response to a POST
/// may be a short event stream: the answer, possibly preceded by
/// notifications). Empty priming events are skipped.
fn sse_messages(body: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut data = String::new();
    for line in body.lines().chain(std::iter::once("")) {
        if let Some(d) = line.strip_prefix("data:") {
            data.push_str(d.strip_prefix(' ').unwrap_or(d));
        } else if line.is_empty() {
            if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                out.push(v);
            }
            data.clear();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_messages_from_an_event_stream() {
        let body = "data: 
id: 0
retry: 3000

data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}

data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}
";
        let msgs = sse_messages(body);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1]["id"], 1);
    }
}
