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
How to use Centuria SAF
To start the protection engine, ensure you have Rust installed and follow these steps:

Build the Project: Generate the optimized binary with cargo build --release.

Launch: Run the firewall using cargo run. The system will immediately load security policies from config.toml.

Real-time Monitoring: The terminal will display live logs. Valid packets are marked in green, while DDoS attempts, unauthorized IPs, or malformed packets (DPI Rejects) will appear in red.

Verification: Use the python3 tester.py script to simulate sensor traffic and verify that the SAF correctly forwards legitimate data or drops malicious payloads.

⚙️ Configuring for an existing SCADA network
Integrating the SAF into a production industrial environment is seamless and does not require modifying your PLCs or existing sensors:

Strategic Positioning: Deploy the SAF (on an Industrial PC or Linux Gateway) between your field sensors and the central SCADA/HMI server.

IP Routing: In config.toml, set listen_addr to the SAF's IP and target_addr to the IP of your SCADA Collector/Historian.

Sensor Whitelisting: Under the [[sensors]] section, add every authorized device by specifying its static IP and the protocol it uses (e.g., centuria or modbus).

Threshold Tuning: Adjust the max_pps (Packets Per Second) based on your hardware's sampling rate. For example, if a sensor sends data every 100ms, a value of max_pps = 15 provides a safe buffer while preventing DDoS floods.

🚨 Alerting Note
To receive mobile notifications, remember to paste your Discord or Slack Webhook URL in the [alerts] section of config.toml and set enabled = true. This ensures you are notified of critical SCADA security events even when you are away from the control room.

Would you like me to create a "Troubleshooting" section in English in case the sensors have connectivity issues?
