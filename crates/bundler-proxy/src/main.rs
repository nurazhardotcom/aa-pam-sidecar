use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde_json::Value;
use std::net::SocketAddr;

mod filter;
use filter::{ALLOWED_CHAIN_ID, ALLOWED_ENTRYPOINT};

#[derive(Clone)]
struct Cfg {
    upstream: String,
    client: reqwest::Client,
}

fn rpc_err(code: i64, msg: &str) -> Value {
    serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":code,"message":msg}})
}

fn domain_chain_id(uop: &Value) -> u64 {
    // Accept hex-string or number. Default = allowed (EntryPoint enforces exact).
    if let Some(s) = uop.get("chainId").and_then(|v| v.as_str()) {
        let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        if let Ok(n) = u64::from_str_radix(h, 16) {
            return n;
        }
    }
    if let Some(n) = uop.get("chainId").and_then(|v| v.as_u64()) {
        return n;
    }
    ALLOWED_CHAIN_ID
}

fn inspect_userop(uop: &Value) -> Result<(), &'static str> {
    // EIP-712 domain bounds. Full ecrecover stays on-chain in EntryPoint.
    if domain_chain_id(uop) != ALLOWED_CHAIN_ID {
        return Err("domain chainId out of bounds");
    }
    if let Some(ep) = uop.get("entryPoint").and_then(|v| v.as_str()) {
        if !ep.eq_ignore_ascii_case(ALLOWED_ENTRYPOINT) {
            return Err("domain verifyingContract not allowlisted");
        }
    }
    filter::check_size_bounds(uop)?;
    filter::check_gas_bounds(uop)?;
    Ok(())
}

async fn proxy(State(cfg): State<Cfg>, body: String) -> (StatusCode, Json<Value>) {
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(rpc_err(-32700, "parse error"))),
    };
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method == "eth_sendUserOperation" || method == "eth_estimateUserOperationGas" {
        match v.get("params").and_then(|p| p.get(0)) {
            Some(uop) => {
                if let Err(e) = inspect_userop(uop) {
                    return (StatusCode::FORBIDDEN, Json(rpc_err(-32000, e)));
                }
            }
            None => return (StatusCode::BAD_REQUEST, Json(rpc_err(-32602, "missing userop"))),
        }
    }
    match cfg
        .client
        .post(&cfg.upstream)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(r) => {
            let j: Value = r.json().await.unwrap_or_else(|_| rpc_err(-32603, "bad upstream"));
            (StatusCode::OK, Json(j))
        }
        Err(_) => (StatusCode::BAD_GATEWAY, Json(rpc_err(-32603, "upstream down"))),
    }
}

#[tokio::main]
async fn main() {
    let cfg = Cfg {
        upstream: std::env::var("BUNDLER_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
        client: reqwest::Client::new(),
    };
    let app = Router::new().route("/rpc", post(proxy)).with_state(cfg);
    let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
