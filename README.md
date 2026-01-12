# SAF---Scada-Proactive-and-reposive-Firewall
Centuria SAF | A high-performance Industrial Protocol Firewall (SAF) written in Rust. Features Deep Packet Inspection (DPI) for SCADA protocols, real-time DDoS mitigation, and instant Webhook security alerts.
# Centuria SAF (SCADA Application Firewall) 🛡️

Centuria SAF is a high-performance, asynchronous **Industrial Protocol Firewall** (SAF) written in Rust. Designed for critical infrastructure protection, it provides **Deep Packet Inspection (DPI)**, proactive **DDoS mitigation**, and real-time security alerts.

Unlike traditional Web Application Firewalls (WAF), Centuria SAF operates at the application layer of industrial UDP-based protocols, ensuring that only authorized sensors can communicate with SCADA controllers using valid protocol structures.



## Key Features

* **Deep Packet Inspection (DPI)**: Validates binary payloads for specific SCADA protocols (Modbus, Centuria, etc.) to prevent malformed packet exploits.
* **DDoS Protection**: Per-IP Rate Limiting (Packets Per Second) powered by the `governor` algorithm.
* **Hot-Reload Configuration**: Update sensor whitelists, protocols, and security policies in `config.toml` without service interruption.
* **Real-time Webhook Alerts**: Instant notifications to Discord, Slack, or Microsoft Teams when attacks or violations are detected.
* **IP Blacklisting**: Automatic banning of malicious sources after repeated security violations.
* **High Performance**: Built on the `Tokio` runtime for sub-millisecond latency in industrial environments.

## Project Structure

```text
centuria-saf/
├── Cargo.toml          # Rust dependencies & metadata
├── config.toml         # Security policies & sensor whitelist
├── tester.py           # Simulation script for security testing
└── src/
    └── main.rs         # Core SAF engine (DPI, Rate Limiter, Alerts)

Project is still in development -----
