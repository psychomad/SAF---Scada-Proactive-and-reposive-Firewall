use tokio::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use axum::{routing::get, Json, Router, extract::State};
use tower_http::cors::CorsLayer;
use std::fs;
use std::path::Path;
use std::num::NonZeroU32;
use notify::{Watcher, RecursiveMode};
use governor::{Quota, RateLimiter, state::direct::NotKeyed};

// --- DATA STRUCTURES ---

#[derive(Deserialize, Clone, Debug)]
struct Config {
    server: ServerConfig,
    sensors: Vec<Sensor>,
    alerts: AlertConfig,
}

#[derive(Deserialize, Clone, Debug)]
struct Sensor { id: String, ip: std::net::IpAddr, protocol: String }

#[derive(Deserialize, Clone, Debug)]
struct ServerConfig { listen_addr: String, target_addr: String, max_pps: u32 }

#[derive(Deserialize, Clone, Debug)]
struct AlertConfig { webhook_url: String, enabled: bool }

#[derive(Serialize)]
struct Stats {
    total_packets: u64,
    blocked_packets: u64,
    active_blacklist_count: usize,
}

struct WafState {
    blacklist: DashMap<std::net::IpAddr, u32>,
    limiters: DashMap<std::net::IpAddr, Arc<RateLimiter<NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>,
    config: ArcSwap<Config>,
    http_client: reqwest::Client,
    total_processed: AtomicU64,
    total_blocked: AtomicU64,
}

// --- WEB SERVER HANDLER ---

async fn get_stats(State(state): State<Arc<WafState>>) -> Json<Stats> {
    Json(Stats {
        total_packets: state.total_processed.load(Ordering::Relaxed),
        blocked_packets: state.total_blocked.load(Ordering::Relaxed),
        active_blacklist_count: state.blacklist.len(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let initial_config = load_config().expect("config.toml not found!");
    let state = Arc::new(WafState {
        blacklist: DashMap::new(),
        limiters: DashMap::new(),
        config: ArcSwap::from_pointee(initial_config),
        http_client: reqwest::Client::new(),
        total_processed: AtomicU64::new(0),
        total_blocked: AtomicU64::new(0),
    });

    // --- HOT RELOAD WATCHER ---
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

    // --- WEB SERVER FOR GUI ---
    let app_state = Arc::clone(&state);
    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        println!("{} http://localhost:3000/api/stats", " API SERVER ONLINE:".green().bold());
        axum::serve(listener, app).await.unwrap();
    });

    // --- UDP CORE ENGINE ---
    let listen_addr = state.config.load().server.listen_addr.clone();
    let socket = Arc::new(UdpSocket::bind(&listen_addr).await?);

    println!("{}", "===============================================".cyan());
    println!("{}", "   CENTURIA SAF v1.2 - CORE ENGINE             ".bold().cyan());
    println!("   Status: {} | API: {}", "ONLINE".green(), "3000".blue());
    println!("{}", "===============================================".cyan());

    let mut buf = [0u8; 4096];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let state = Arc::clone(&state);
        let socket = Arc::clone(&socket);
        let packet = buf[..len].to_vec();

        tokio::spawn(async move {
            state.total_processed.fetch_add(1, Ordering::Relaxed);
            let ip = src.ip();
            let cfg = state.config.load();

            if state.blacklist.get(&ip).map_or(false, |f| *f >= 10) {
                state.total_blocked.fetch_add(1, Ordering::Relaxed);
                return;
            }

            let limiter = state.limiters.entry(ip).or_insert_with(|| {
                let pps = NonZeroU32::new(cfg.server.max_pps).unwrap_or(NonZeroU32::new(1).unwrap());
                Arc::new(RateLimiter::direct(Quota::per_second(pps)))
            });

            if let Err(_) = limiter.check() {
                log_event("DDOS_ATTACK", &format!("Rate limit exceeded for {}", ip), src, "red");
                state.total_blocked.fetch_add(1, Ordering::Relaxed);
                state.blacklist.insert(ip, 100);
                return;
            }

            let sensor = cfg.sensors.iter().find(|s| s.ip == ip);
            if sensor.is_none() || !validate_packet(&sensor.unwrap().protocol, &packet) {
                log_event("SECURITY_REJECT", "Invalid protocol or unauthorized IP", src, "red");
                state.total_blocked.fetch_add(1, Ordering::Relaxed);
                state.blacklist.entry(ip).and_modify(|e| *e += 1).or_insert(1);
                return;
            }

            let _ = socket.send_to(&packet, &cfg.server.target_addr).await;
        });
    }
}

fn validate_packet(proto: &str, data: &[u8]) -> bool {
    match proto {
        "centuria" => data.len() >= 5 && data.starts_with(b"CE"),
        "modbus" => data.len() >= 7 && data[0] != 0,
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
