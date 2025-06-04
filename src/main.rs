use std::{convert::Infallible, fs, net::IpAddr, sync::Arc};

use log::{error, info};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;
use warp::{http::StatusCode, reply, Filter};

#[derive(Debug, Deserialize)]
struct Config {
    zone_id: String,
    record_name: String,
    api_token: String,
    proxied: Option<bool>,
    ttl: Option<u32>,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    // Load config from /etc/cloudflare-dyndns/config.toml
    let cfg_str = match fs::read_to_string("/etc/cloudflare-dyndns/config.toml") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read config.toml: {}", e);
            std::process::exit(1);
        }
    };

    let config: Config = match toml::from_str(&cfg_str) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config.toml: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        "Loaded config: zone_id={}, record_name={}",
        config.zone_id, config.record_name
    );

    // Share config via Arc<Mutex<...>> so we can clone into handlers
    let shared_config = Arc::new(Mutex::new(config));

    // Define a Warp filter for GET /update?myip=<IPv6>
    let update_route = warp::path("update")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(with_config(shared_config.clone()))
        .and_then(handle_update);

    // Bind to 0.0.0.0:8888
    let addr = ([0, 0, 0, 0], 8888);
    info!("Starting HTTP server on http://[::]:8888");
    warp::serve(update_route).run(addr).await;
}

/// Inject the shared config into the route handler
fn with_config(
    cfg: Arc<Mutex<Config>>,
) -> impl Filter<Extract = (Arc<Mutex<Config>>,), Error = Infallible> + Clone {
    warp::any().map(move || cfg.clone())
}

/// Handler for `/update?myip=<addr>`
async fn handle_update(
    params: std::collections::HashMap<String, String>,
    cfg_mutex: Arc<Mutex<Config>>,
) -> Result<impl warp::Reply, Infallible> {
    let ip_str = match params.get("myip") {
        Some(s) => s,
        None => {
            let reply = reply::with_status(
                reply::html("Missing myip parameter".to_string()),
                StatusCode::BAD_REQUEST,
            );
            return Ok(reply);
        }
    };

    // Parse IP address
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let reply = reply::with_status(
                reply::html("Invalid IP format".to_string()),
                StatusCode::BAD_REQUEST,
            );
            return Ok(reply);
        }
    };

    let config = cfg_mutex.lock().await;
    match update_cloudflare_dns(&config, ip).await {
        Ok(msg) => {
            info!("{}", msg);
            let reply = reply::with_status(reply::html(msg), StatusCode::OK);
            Ok(reply)
        }
        Err(err_msg) => {
            error!("{}", err_msg);
            let reply = reply::with_status(reply::html(err_msg), StatusCode::INTERNAL_SERVER_ERROR);
            Ok(reply)
        }
    }
}

/// Query Cloudflare for existing AAAA record, then update it to `ip`
async fn update_cloudflare_dns(cfg: &Config, ip: IpAddr) -> Result<String, String> {
    // 1. Build Authorization header
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bearer {}", cfg.api_token);
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth_value).map_err(|e| format!("Bad token header: {}", e))?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // 2. Get record ID
    let client = reqwest::Client::new();
    let list_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=AAAA&name={}",
        cfg.zone_id, cfg.record_name
    );
    let list_resp = client
        .get(&list_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|e| format!("Failed to query DNS records: {}", e))?;

    let list_json: Value = list_resp
        .json()
        .await
        .map_err(|e| format!("Malformed JSON from Cloudflare: {}", e))?;

    // Extract record ID (assume first match)
    let record_id = list_json["result"]
        .as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|r| r.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "No existing AAAA record found".to_string())?;

    // 3. PUT update with new IP
    let update_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        cfg.zone_id, record_id
    );

    // Build body JSON
    let body = serde_json::json!({
        "type": "AAAA",
        "name": cfg.record_name,
        "content": ip.to_string(),
        "ttl": cfg.ttl.unwrap_or(300),
        "proxied": cfg.proxied.unwrap_or(true)
    });

    let update_resp = client
        .put(&update_url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to send update: {}", e))?;

    let update_json: Value = update_resp
        .json()
        .await
        .map_err(|e| format!("Malformed JSON on update: {}", e))?;

    if update_json["success"].as_bool().unwrap_or(false) {
        Ok(format!("Successfully updated DNS to {}", ip))
    } else {
        let errs = update_json["errors"].clone();
        Err(format!("Cloudflare API error: {}", errs))
    }
}
