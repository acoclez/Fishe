//! The MCP server on the official Rust SDK (`rmcp`): Streamable HTTP via
//! `StreamableHttpService` (protocol negotiation, sessions, `Host` / `Origin`
//! validation, JSON responses), served by axum on a small tokio runtime of
//! its own ([`runtime`]) with a graceful, port-releasing shutdown. Fishe adds
//! the bearer-token check and the access-level-filtered tools
//! ([`super::tools`]).

use crate::services::Services;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeRequestParams, InitializeResult, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const INSTRUCTIONS: &str = "Fishe measures this computer's network traffic in real time: \
a remote host, one program, or all traffic labelled by program. Start with get_status. \
Rates are bytes per second; levels (idle/calm/busy/spike) compare traffic to its own learned normal. \
RTT and retransmissions come from passive TCP analysis; UDP traffic has no RTT unless pinged. \
Use wait_for_traffic to be told when traffic gets busy instead of polling. \
Which tools exist depends on the access level the user granted in Fishe (read / control / network).";

/// One instance per MCP session (created by the service factory). Weak: the
/// server is owned by the services it serves.
#[derive(Clone)]
struct FisheMcp {
    svc: Weak<Services>,
}

impl FisheMcp {
    fn services(&self) -> Result<Arc<Services>, McpError> {
        self.svc
            .upgrade()
            .ok_or_else(|| McpError::internal_error("Fishe is shutting down", None))
    }
}

/// The server's async runtime: two workers for the HTTP side, tools on its
/// blocking pool. Its own, so the server runs the same with or without a
/// window. Lives as long as the process.
fn runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("fishe-mcp")
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the MCP runtime: {e}"))?;
    Ok(RUNTIME.get_or_init(|| rt))
}

fn client_name(ctx: &RequestContext<RoleServer>) -> String {
    ctx.peer
        .peer_info()
        .map(|p| {
            format!("{} {}", p.client_info.name, p.client_info.version)
                .trim()
                .to_string()
        })
        .unwrap_or_default()
}

impl ServerHandler for FisheMcp {
    fn get_info(&self) -> ServerConfig {
        let mut server = Implementation::new("fishe", env!("CARGO_PKG_VERSION"));
        server.title = Some("Fishe".into());
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server)
            .with_instructions(INSTRUCTIONS)
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let access = self.services()?.mcp.access();
        let tools = super::tools::list(access)
            .into_iter()
            .filter_map(to_tool)
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let svc = self.services()?;
        let client = client_name(&context);
        let params = serde_json::json!({
            "name": request.name,
            "arguments": request.arguments.map(Value::Object).unwrap_or_else(|| serde_json::json!({})),
        });
        // Tools block (traceroute, wait_for_traffic): keep them off the async workers.
        let outcome =
            tokio::task::spawn_blocking(move || super::tools::call(&svc, &params, &client))
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let value = outcome.map_err(|(_, message)| McpError::invalid_params(message, None))?;
        Ok(CallToolResponse::Complete(to_result(value)))
    }
}

/// Our tool JSON (shared with the tests) → rmcp's `Tool`.
fn to_tool(v: Value) -> Option<Tool> {
    let name = v.get("name")?.as_str()?.to_string();
    let description = v.get("description")?.as_str()?.to_string();
    let schema = v.get("inputSchema")?.as_object()?.clone();
    let mut tool = Tool::new(name, description, Arc::new(schema));
    tool.title = v.get("title").and_then(Value::as_str).map(String::from);
    let a = v.get("annotations");
    let flag = |k: &str| a.and_then(|a| a.get(k)).and_then(Value::as_bool);
    let mut ann = ToolAnnotations::new();
    ann.title = tool.title.clone();
    ann.read_only_hint = flag("readOnlyHint");
    ann.destructive_hint = flag("destructiveHint");
    ann.idempotent_hint = flag("idempotentHint");
    ann.open_world_hint = flag("openWorldHint");
    tool.annotations = Some(ann);
    Some(tool)
}

/// Our `{content, structuredContent, isError}` → rmcp's `CallToolResult`.
fn to_result(v: Value) -> CallToolResult {
    let text = v
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let is_error = v.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let mut result = if is_error {
        CallToolResult::error(vec![ContentBlock::text(text)])
    } else {
        CallToolResult::success(vec![ContentBlock::text(text)])
    };
    if !is_error {
        result.structured_content = v.get("structuredContent").cloned();
    }
    result
}

/// Bearer token on every request; the token is read from the live settings.
async fn auth(svc: Weak<Services>, req: Request, next: Next) -> Response {
    let Some(token) = svc.upgrade().map(|s| s.mcp.token()) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Fishe is shutting down").into_response();
    };
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(format!("Bearer {token}").as_str());
    if ok {
        next.run(req).await
    } else {
        // 403, not 401: MCP clients answer any 401 by starting an OAuth
        // sign-in, which Fishe doesn't offer (it uses a static token), so a
        // stale token would show up as a confusing login prompt.
        (
            StatusCode::FORBIDDEN,
            "missing or wrong bearer token: copy the current one from Fishe → Settings → Agents (MCP)",
        )
            .into_response()
    }
}

/// A running server; dropping it shuts it down and frees the port.
pub struct Handle {
    cancel: CancellationToken,
    done: Option<mpsc::Receiver<()>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(done) = self.done.take() {
            let _ = done.recv_timeout(Duration::from_secs(3));
        }
    }
}

pub fn serve(svc: Weak<Services>, port: u16) -> Result<Handle, String> {
    let runtime = runtime()?;
    // Bind synchronously so a busy port is reported to the caller at once.
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let cancel = CancellationToken::new();
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts([format!("127.0.0.1:{port}"), format!("localhost:{port}")])
        .with_allowed_origins([
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
        ])
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_max_request_body_bytes(1024 * 1024)
        .with_cancellation_token(cancel.child_token());
    let factory_svc = svc.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(FisheMcp {
                svc: factory_svc.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(move |req, next| {
            auth(svc.clone(), req, next)
        }));

    let (tx, rx) = mpsc::channel();
    let shutdown = cancel.clone();
    runtime.spawn(async move {
        match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => {
                let server = axum::serve(listener, router)
                    .with_graceful_shutdown(async move { shutdown.cancelled().await });
                if let Err(e) = server.await {
                    log::warn!("MCP server stopped: {e}");
                }
            }
            Err(e) => log::warn!("MCP listener: {e}"),
        }
        let _ = tx.send(());
    });
    Ok(Handle {
        cancel,
        done: Some(rx),
    })
}
