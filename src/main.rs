use tokio::net::UdpSocket;
use std::sync::Arc;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use notify::{Watcher, RecursiveMode};
use governor::{Quota, RateLimiter, state::direct::NotKeyed};
use nonzero_ext::*;

#[derive(Deserialize, Clone, Debug)]
struct Sensor {
    id: String,
    ip: std::net::IpAddr,
    protocol: String,
}

#[derive(Deserialize, Clone, Debug)]
struct Config {
    server: ServerConfig,
    sensors: Vec<Sensor>,
    alerts: AlertConfig,
}

#[derive(Deserialize, Clone, Debug)]
struct ServerConfig {
    listen_addr: String,
    target_addr: String,
    max_pps: u32,
}

#[derive(Deserialize, Clone, Debug)]
struct AlertConfig {
    webhook_url: String,
    enabled: bool,
}

#[derive(Serialize)]
struct WebhookPayload {
    content: String,
}

struct WafState {
    blacklist: DashMap<std::net::IpAddr, u32>,
    limiters: DashMap<std::net::IpAddr, Arc<RateLimiter<NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>,
    config: ArcSwap<Config>,
    http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let initial_config = load_config()?;
    let state = Arc::new(WafState {
        blacklist: DashMap::new(),
        limiters: DashMap::new(),
        config: ArcSwap::from_pointee(initial_config),
        http_client: reqwest::Client::new(),
    });

    // Monitoraggio config.toml
    let state_clone = Arc::clone(&state);
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(_) = res {
            if let Ok(new_cfg) = load_config() {
                state_clone.config.store(Arc::new(new_cfg));
                println!("{}", "--- [SAF] SECURITY POLICIES RELOADED ---".magenta().bold());
            }
        }
    })?;
    watcher.watch(Path::new("config.toml"), RecursiveMode::NonRecursive)?;

    let listen_addr = state.config.load().server.listen_addr.clone();
    let socket = Arc::new(UdpSocket::bind(&listen_addr).await?);

    println!("{}", "===============================================".cyan());
    println!("{}", "   CENTURIA SAF v1.1 - ALERT SYSTEM ACTIVE     ".bold().cyan());
    println!("   Webhook Alerts: {}", if state.config.load().alerts.enabled { "ENABLED".green() } else { "DISABLED".red() });
    println!("{}", "===============================================".cyan());

    let mut buf = [0u8; 4096];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let state = Arc::clone(&state);
        let socket = Arc::clone(&socket);
        let packet = buf[..len].to_vec();

        tokio::spawn(async move {
            let ip = src.ip();
            let cfg = state.config.load();

            if state.blacklist.get(&ip).map_or(false, |f| *f >= 10) { return; }

            let limiter = state.limiters.entry(ip).or_insert_with(|| {
                Arc::new(RateLimiter::direct(Quota::per_second(nonzero!(cfg.server.max_pps))))
            });

            if let Err(_) = limiter.check() {
                let msg = format!("DDoS Attack detected from IP: {}", ip);
                log_event("DDOS_ATTACK", &msg, src, "red");
                send_alert(&state, &msg).await;
                state.blacklist.insert(ip, 100);
                return;
            }

            let sensor = cfg.sensors.iter().find(|s| s.ip == ip);
            if sensor.is_none() {
                log_event("UNAUTHORIZED", "Possible Redirect/Spoofing", src, "red");
                return;
            }
            let s_info = sensor.unwrap();

            if !validate_packet(&s_info.protocol, &packet) {
                let msg = format!("Malformed packet (DPI Reject) from Sensor: {}", s_info.id);
                log_event("MALFORMED", &msg, src, "red");
                send_alert(&state, &msg).await;
                let mut entry = state.blacklist.entry(ip).or_insert(0);
                *entry += 1;
                return;
            }

            let _ = socket.send_to(&packet, &cfg.server.target_addr).await;
        });
    }
}

async fn send_alert(state: &WafState, message: &str) {
    let cfg = state.config.load();
    if !cfg.alerts.enabled { return; }

    let payload = WebhookPayload {
        content: format!("⚠️ **CENTURIA SAF ALERT** ⚠️\n> {}", message),
    };

    let _ = state.http_client
        .post(&cfg.alerts.webhook_url)
        .json(&payload)
        .send()
        .await;
}

fn validate_packet(proto: &str, data: &[u8]) -> bool {
    match proto {
        "centuria" => data.len() >= 5 && data.starts_with(b"CE"),
        "modbus" => data.len() >= 7 && data[7] <= 127,
        _ => !data.is_empty(),
    }
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let s = fs::read_to_string("config.toml")?;
    Ok(toml::from_str(&s)?)
}

fn log_event(event: &str, details: &str, src: std::net::SocketAddr, color: &str) {
    let evt = if color == "red" { event.red().bold() } else { event.green().bold() };
    println!("[{}] {} | SRC: {} | {}", Utc::now().format("%H:%M:%S"), evt, src.to_string().yellow(), details);
}


