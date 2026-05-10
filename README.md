# 🛡️ Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System built with **Python**, **Scapy**, and **MySQL/MariaDB** that monitors live network traffic, detects suspicious activity, and stores all alerts in a database.

---

## 🎯 Features

| Detection Engine | What It Catches |
|---|---|
| 🔍 Port Scan Detection | IP hitting 15+ unique ports within 5 seconds |
| 💥 Traffic Spike / DoS | Single IP exceeding 200 packets/sec |
| 🚫 Malicious IP Blocklist | Packets from known bad IPs |
| ⚠️ Suspicious Port Probe | Access to ports: 22, 23, 3389, 4444, 5900, 6667, 31337 |
| 📡 ICMP Flood Detection | 50+ pings from one IP in under 2 seconds |

---

## 📸 Screenshots

### Simulation Running
![Simulation](screenshots/1_simulation(1).png,simulation(2).png,simulation(3).png,simulation(4).png,simulation(5).png)

### Database Output
![Show DB](screenshots/2_show_db.png)

### MariaDB Query
![MariaDB](screenshots/3_mariadb_query.png)

---

## 📁 Project Structure

```
nids/
├── nids.py              # Main detection script
├── requirements.txt     # Dependencies
├── screenshots/         # Project screenshots
│   ├── 1_simulation.png
│   ├── 2_show_db.png
│   └── 3_mariadb_query.png
├── nids_alerts.log      # Human-readable alert log (auto-generated)
├── packets.jsonl        # JSON structured log (auto-generated)
└── README.md
```

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/Adithya221021/nids.git
cd nids

# Install dependencies
pip install -r requirements.txt

# Install MariaDB (Kali Linux)
sudo apt install mariadb-server -y
sudo service mariadb start
```

---

## 🗄️ Database Setup

```bash
sudo mysql
```

```sql
CREATE DATABASE nids_db;
USE nids_db;

CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    level VARCHAR(10),
    category VARCHAR(50),
    src_ip VARCHAR(20),
    details TEXT
);

CREATE TABLE packets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    src_ip VARCHAR(20),
    dst_ip VARCHAR(20),
    protocol VARCHAR(10),
    port INT
);

CREATE USER 'nids_user'@'localhost' IDENTIFIED BY 'nids1234';
GRANT ALL PRIVILEGES ON nids_db.* TO 'nids_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 🚀 Usage

### Simulation Mode (no root required)
```bash
python3 nids.py --simulate
```

### View Alerts from Database
```bash
python3 nids.py --show-db
```

### Live Capture Mode (requires root)
```bash
# List interfaces first
sudo python3 nids.py --list-interfaces

# Start live capture
sudo python3 nids.py -i eth0       # wired
sudo python3 nids.py -i wlan0      # WiFi
```

---

## 📋 Sample Output

```
  ╔══════════════════════════════════════════════════════╗
  ║      🛡️  NETWORK INTRUSION DETECTION SYSTEM          ║
  ║           Python + Scapy + MySQL  •  v2.0            ║
  ╚══════════════════════════════════════════════════════╝

  ✅ Database connected (nids_db)

  📡 Scenario: Port scan from attacker
  [TCP] 10.0.0.77 → 192.168.0.1:1031
  [TCP] 10.0.0.77 → 192.168.0.1:1038

🔴 [HIGH] PORT SCAN DETECTED — 10.0.0.77 — 20 unique ports in 5s
🔴 [HIGH] KNOWN MALICIOUS IP — 192.168.1.100 — IP found in blocklist
🟡 [MEDIUM] SUSPICIOUS PORT ACCESS — 172.16.0.50 — Port 22 (SSH)
🟡 [MEDIUM] ICMP FLOOD DETECTED — 10.0.0.88 — 60 ICMP packets in 2s
🔴 [HIGH] TRAFFIC SPIKE / POSSIBLE DoS — 10.0.0.99 — 300 pkt/s
```

---

## 📊 Log Files

**`nids_alerts.log`** — timestamped human-readable log:
```
2026-05-08 16:08:23 [WARNING] 🔴 [HIGH] PORT SCAN DETECTED — 10.0.0.77
2026-05-08 16:08:25 [INFO]    🟡 [MEDIUM] SUSPICIOUS PORT ACCESS — 172.16.0.50
```

**`packets.jsonl`** — structured JSON, one alert per line:
```json
{"timestamp": "2026-05-08T16:08:23", "level": "HIGH", "category": "PORT SCAN DETECTED", "src_ip": "10.0.0.77", "details": "20 unique ports in 5s"}
```

---

## 🔧 Configuration

Edit the `CONFIG` dictionary in `nids.py`:

```python
CONFIG = {
    "port_scan_threshold": 15,       # ports hit before alerting
    "port_scan_window": 5,           # time window in seconds
    "traffic_spike_threshold": 200,  # packets/sec to trigger DoS alert
    "suspicious_ips": [              # add your blocklist here
        "192.168.1.100",
    ],
    "suspicious_ports": [            # high-risk ports to monitor
        22, 23, 3389, 4444, 5900, 6667, 31337
    ],
}
```

---

## 🛠️ Tech Stack

- **Python 3.x**
- **Scapy** — packet capture and analysis
- **MySQL / MariaDB** — alert and packet storage
- **mysql-connector-python** — database connectivity
- **logging** — structured alert logging
- **argparse** — CLI interface
- **collections.defaultdict** — efficient traffic state tracking

---

## 📌 Requirements

```
scapy>=2.5.0
mysql-connector-python
```

---

## 🔒 Disclaimer

This tool is intended for **educational purposes** and **authorized network monitoring only**. Always obtain proper permission before monitoring any network you do not own.

---

## 👤 Author

**Adithya**
- GitHub: [@Adithya221021](https://github.com/Adithya221021)
- Email: adithya45799@gmail.com

Built as a cybersecurity portfolio project demonstrating real-time network traffic analysis, threat detection, and database integration using Python.
