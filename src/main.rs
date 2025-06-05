use std::{convert::Infallible, fs, net::IpAddr, sync::Arc};

use log::{debug, error, info, warn};
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

    let cfg_path = "/etc/cloudflare-dyndns/config.toml";

    let cfg_str = match fs::read_to_string(cfg_path) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read config file at {}: {}", cfg_path, e);
            std::process::exit(1);
        }
    };

    let config: Config = match toml::from_str(&cfg_str) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse TOML config at {}: {}", cfg_path, e);
            std::process::exit(1);
        }
    };

    info!(
        "Loaded config: zone_id='{}', record_name='{}'",
        config.zone_id, config.record_name
    );

    let shared_config = Arc::new(Mutex::new(config));

    let update_route = warp::path("update")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::addr::remote()) // get peer IP
        .and(with_config(shared_config.clone()))
        .and_then(handle_update);

    let addr = ([0, 0, 0, 0], 8888);
    info!("Starting HTTP server on http://0.0.0.0:{}", addr.1);
    warp::serve(update_route)
        .tls()
        .cert_path("/etc/cloudflare-dyndns/tls/server.crt")
        .key_path("/etc/cloudflare-dyndns/tls/server.key")
        .run(addr)
        .await;
}

fn with_config(
    cfg: Arc<Mutex<Config>>,
) -> impl Filter<Extract = (Arc<Mutex<Config>>,), Error = Infallible> + Clone {
    warp::any().map(move || cfg.clone())
}

async fn handle_update(
    params: std::collections::HashMap<String, String>,
    remote: Option<std::net::SocketAddr>,
    cfg_mutex: Arc<Mutex<Config>>,
) -> Result<impl warp::Reply, Infallible> {
    let client_ip = remote
        .map(|r| r.ip())
        .unwrap_or_else(|| "unknown".parse().unwrap());

    info!(
        "Incoming update request from {} with params {:?}",
        client_ip, params
    );

    let ip_str = match params.get("myip") {
        Some(s) => s,
        None => {
            warn!("Request from {} missing 'myip' parameter", client_ip);
            let reply = reply::with_status(
                reply::html("Missing myip parameter".to_string()),
                StatusCode::BAD_REQUEST,
            );
            return Ok(reply);
        }
    };

    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!("Invalid IP '{}' received from {}", ip_str, client_ip);
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
            info!(
                "Update successful for {} -> {}: {}",
                config.record_name, ip, msg
            );
            let reply = reply::with_status(reply::html(msg), StatusCode::OK);
            Ok(reply)
        }
        Err(err_msg) => {
            error!(
                "DNS update failed for {} -> {}: {}",
                config.record_name, ip, err_msg
            );
            let reply = reply::with_status(reply::html(err_msg), StatusCode::INTERNAL_SERVER_ERROR);
            Ok(reply)
        }
    }
}

async fn update_cloudflare_dns(cfg: &Config, ip: IpAddr) -> Result<String, String> {
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bearer {}", cfg.api_token);
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth_value).map_err(|e| format!("Bad token header: {}", e))?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let client = reqwest::Client::new();

    // Step 1: Query current records
    let list_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=AAAA&name={}",
        cfg.zone_id, cfg.record_name
    );
    debug!("Querying existing DNS records: {}", list_url);

    let list_resp = client
        .get(&list_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|e| format!("Failed to query DNS records: {}", e))?;

    let list_status = list_resp.status();
    let list_json: Value = list_resp
        .json()
        .await
        .map_err(|e| format!("Malformed JSON from Cloudflare: {}", e))?;
    debug!(
        "Cloudflare list response (status {}): {}",
        list_status, list_json
    );

    let record_id = list_json["result"]
        .as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|r| r.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "No existing AAAA record found".to_string())?;

    // Step 2: Update DNS record
    let update_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        cfg.zone_id, record_id
    );
    debug!("Sending DNS update to: {}", update_url);

    let body = serde_json::json!({
        "type": "AAAA",
        "name": cfg.record_name,
        "content": ip.to_string(),
        "ttl": cfg.ttl.unwrap_or(300),
        "proxied": cfg.proxied.unwrap_or(true)
    });

    debug!("Update request body: {}", body);

    let update_resp = client
        .put(&update_url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to send update: {}", e))?;

    let update_status = update_resp.status();
    let update_json: Value = update_resp
        .json()
        .await
        .map_err(|e| format!("Malformed JSON on update: {}", e))?;

    debug!(
        "Cloudflare update response (status {}): {}",
        update_status, update_json
    );

    if update_json["success"].as_bool().unwrap_or(false) {
        Ok(format!("Successfully updated DNS to {}", ip))
    } else {
        let errs = update_json["errors"].clone();
        Err(format!("Cloudflare API error: {}", errs))
    }
}
