use crate::errors::{Result, RpcError};
use crate::state::{BankAccessProvider, RuntimeSnapshotProvider, TransactionSubmitter};
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::json;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use tracing::{error, info};

use super::registry::REGISTERED_RPC_METHODS;
use super::renderer::render_json_rpc_response_with_dev_mode;
use super::subscriptions::register_subscription_methods;

pub fn spawn_rpc_http_server(
    bind_addr: SocketAddr,
    full_api: bool,
    private: bool,
    dev_mode: bool,
    runtime_snapshot_provider: Option<Arc<dyn RuntimeSnapshotProvider>>,
    bank_access_provider: Option<Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<Arc<dyn TransactionSubmitter>>,
) -> Result<()> {
    let bind_probe = TcpListener::bind(bind_addr)
        .map_err(|source| RpcError::RpcHttpBind { bind_addr, source })?;
    drop(bind_probe);

    info!(
        %bind_addr,
        full_api,
        private,
        runtime_provider = runtime_snapshot_provider.is_some(),
        "serving JSON-RPC"
    );

    thread::Builder::new()
        .name("rpc-http".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    error!(%error, "failed to build tokio runtime for RPC");
                    return;
                }
            };

            runtime.block_on(async move {
                let server = match ServerBuilder::default().build(bind_addr).await {
                    Ok(server) => server,
                    Err(error) => {
                        error!(%error, "failed to start jsonrpsee server");
                        return;
                    }
                };

                let mut module = RpcModule::new(());
                for method in REGISTERED_RPC_METHODS {
                    // Dev-mode methods are only registered when dev_mode is active.
                    if method.requires_dev_mode() && !dev_mode {
                        continue;
                    }
                    let method_name = method.as_str();
                    let provider = runtime_snapshot_provider.clone();
                    let bank_access = bank_access_provider.clone();
                    let submitter = tx_submitter.clone();
                    let registration =
                        module.register_method(method_name, move |params: Params<'_>, _, _| {
                            dispatch_via_legacy_renderer(
                                method_name,
                                params,
                                full_api,
                                dev_mode,
                                provider.as_ref(),
                                bank_access.as_ref(),
                                submitter.as_ref(),
                            )
                        });
                    if let Err(error) = registration {
                        error!(method = method_name, %error, "failed to register RPC method");
                        return;
                    }
                }

                if let Err(error) = register_subscription_methods(
                    &mut module,
                    full_api,
                    runtime_snapshot_provider.clone(),
                    bank_access_provider.clone(),
                ) {
                    error!(%error, "failed to register RPC subscriptions");
                    return;
                }

                let _handle = server.start(module);
                std::future::pending::<()>().await;
            });
        })
        .map_err(RpcError::RpcHttpThreadSpawn)?;

    Ok(())
}

/// Spawn a dedicated WebSocket-only server on a separate port.
///
/// This mirrors Solana's architecture where HTTP RPC runs on port 8899 and
/// WebSocket subscriptions run on port 8900. The main HTTP server continues
/// to serve both protocols for backward compatibility.
pub fn spawn_rpc_ws_server(
    ws_bind_addr: SocketAddr,
    full_api: bool,
    runtime_snapshot_provider: Option<Arc<dyn RuntimeSnapshotProvider>>,
    bank_access_provider: Option<Arc<dyn BankAccessProvider>>,
) -> Result<()> {
    let bind_probe = TcpListener::bind(ws_bind_addr)
        .map_err(|source| RpcError::RpcHttpBind {
            bind_addr: ws_bind_addr,
            source,
        })?;
    drop(bind_probe);

    info!(%ws_bind_addr, full_api, "serving WebSocket subscriptions");

    thread::Builder::new()
        .name("rpc-ws".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    error!(%error, "failed to build tokio runtime for WS");
                    return;
                }
            };

            runtime.block_on(async move {
                let server = match ServerBuilder::default().build(ws_bind_addr).await {
                    Ok(server) => server,
                    Err(error) => {
                        error!(%error, "failed to start jsonrpsee WS server");
                        return;
                    }
                };

                let mut module = RpcModule::new(());

                if let Err(error) = register_subscription_methods(
                    &mut module,
                    full_api,
                    runtime_snapshot_provider.clone(),
                    bank_access_provider.clone(),
                ) {
                    error!(%error, "failed to register WS subscriptions");
                    return;
                }

                let _handle = server.start(module);
                std::future::pending::<()>().await;
            });
        })
        .map_err(RpcError::RpcHttpThreadSpawn)?;

    Ok(())
}

fn dispatch_via_legacy_renderer(
    method_name: &str,
    params: Params<'_>,
    full_api: bool,
    dev_mode: bool,
    runtime_snapshot_provider: Option<&Arc<dyn RuntimeSnapshotProvider>>,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> std::result::Result<serde_json::Value, ErrorObjectOwned> {
    let request_params = match params.parse::<Option<serde_json::Value>>() {
        Ok(Some(value)) => value,
        Ok(None) => serde_json::Value::Array(Vec::new()),
        Err(_) => {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "Invalid params",
                None::<()>,
            ))
        }
    };
    if !request_params.is_array() {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "Invalid params",
            None::<()>,
        ));
    }
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": method_name,
        "params": request_params
    });

    let runtime_snapshot =
        runtime_snapshot_provider.and_then(|provider| provider.latest_snapshot());

    let response = render_json_rpc_response_with_dev_mode(
        &request_body.to_string(),
        full_api,
        dev_mode,
        runtime_snapshot,
        bank_access,
        tx_submitter,
    );
    let parsed_response: serde_json::Value = serde_json::from_str(&response).map_err(|error| {
        ErrorObjectOwned::owned(-32603, format!("Internal error: {error}"), None::<()>)
    })?;

    if let Some(error) = parsed_response.get("error") {
        let code = error
            .get("code")
            .and_then(|value| value.as_i64())
            .unwrap_or(-32603);
        let message = error
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap_or("Internal error");
        let data = error.get("data").cloned();
        return Err(ErrorObjectOwned::owned(code as i32, message, data));
    }

    Ok(parsed_response
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}
