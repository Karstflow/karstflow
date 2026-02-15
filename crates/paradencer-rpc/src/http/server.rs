use crate::errors::{Result, RpcError};
use crate::state::RuntimeSnapshotProvider;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::json;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;

use super::registry::REGISTERED_RPC_METHODS;
use super::renderer::render_json_rpc_response;
use super::subscriptions::register_subscription_methods;

pub fn spawn_rpc_http_server(
    bind_addr: SocketAddr,
    full_api: bool,
    private: bool,
    runtime_snapshot_provider: Option<Arc<dyn RuntimeSnapshotProvider>>,
) -> Result<()> {
    let bind_probe = TcpListener::bind(bind_addr)
        .map_err(|source| RpcError::RpcHttpBind { bind_addr, source })?;
    drop(bind_probe);

    println!(
        "[rpc-http] serving JSON-RPC on http://{} full_api={} private={} runtime_provider={}",
        bind_addr,
        full_api,
        private,
        runtime_snapshot_provider.is_some()
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
                    eprintln!("[rpc-http] failed to build tokio runtime: {error}");
                    return;
                }
            };

            runtime.block_on(async move {
                let server = match ServerBuilder::default().build(bind_addr).await {
                    Ok(server) => server,
                    Err(error) => {
                        eprintln!("[rpc-http] failed to start jsonrpsee server: {error}");
                        return;
                    }
                };

                let mut module = RpcModule::new(());
                for method in REGISTERED_RPC_METHODS {
                    let method_name = method.as_str();
                    let provider = runtime_snapshot_provider.clone();
                    let registration =
                        module.register_method(method_name, move |params: Params<'_>, _, _| {
                            dispatch_via_legacy_renderer(
                                method_name,
                                params,
                                full_api,
                                provider.as_ref(),
                            )
                        });
                    if let Err(error) = registration {
                        eprintln!("[rpc-http] failed to register method {method_name}: {error}");
                        return;
                    }
                }

                if let Err(error) = register_subscription_methods(
                    &mut module,
                    full_api,
                    runtime_snapshot_provider.clone(),
                ) {
                    eprintln!("[rpc-http] failed to register subscriptions: {error}");
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
    runtime_snapshot_provider: Option<&Arc<dyn RuntimeSnapshotProvider>>,
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

    let response = render_json_rpc_response(&request_body.to_string(), full_api, runtime_snapshot);
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
        return Err(ErrorObjectOwned::owned(code as i32, message, None::<()>));
    }

    Ok(parsed_response
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}
