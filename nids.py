#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║        NETWORK INTRUSION DETECTION SYSTEM (NIDS)         ║
║         Python + Scapy + MySQL/MariaDB  •  v2.0          ║
╚══════════════════════════════════════════════════════════╝
"""

import time
import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict

import mysql.connector

# ─── Try to import Scapy ────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not found. Running in SIMULATION mode.")
    print("    Install with: pip install scapy\n")

# ─── Logging Setup ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("nids_alerts.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NIDS")

# ─── Database Config ────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "user":     "nids_user",
    "password": "nids1234",
    "database": "nids_db",
}

# ─── Detection Config ───────────────────────────────────────
CONFIG = {
    "port_scan_threshold": 15,
    "port_scan_window": 5,
    "traffic_spike_threshold": 200,
    "traffic_spike_window": 3,
    "suspicious_ips": [
        "192.168.1.100",
        "10.0.0.99",
    ],
    "suspicious_ports": [
        22, 23, 3389, 4444, 5900, 6667, 31337
    ],
    "log_file":   "nids_alerts.log",
    "packet_log": "packets.jsonl",
}

# ─── State Tracking ─────────────────────────────────────────
port_access   = defaultdict(lambda: defaultdict(list))
traffic_count = defaultdict(list)
alert_history = []

# ─── Database Connection ────────────────────────────────────
def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        logger.error(f"[DB] Connection failed: {e}")
        return None

def save_alert_to_db(level, category, src_ip, details):
    conn = get_db()
    if not conn:
        return
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, level, category, src_ip, details) "
            "VALUES (%s, %s, %s, %s, %s)",
            (datetime.now(), level, category, src_ip, details)
        )
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"[DB] Alert saved → alerts table")
    except mysql.connector.Error as e:
        logger.error(f"[DB] Failed to save alert: {e}")

def save_packet_to_db(src_ip, dst_ip, protocol, port):
    conn = get_db()
    if not conn:
        return
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, port) "
            "VALUES (%s, %s, %s, %s, %s)",
            (datetime.now(), src_ip, dst_ip, protocol, port)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as e:
        logger.error(f"[DB] Failed to save packet: {e}")

# ─── Alert System ───────────────────────────────────────────
def fire_alert(level, category, src_ip, details):
    icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
    icon  = icons.get(level, "⚠️")

    alert = {
        "timestamp": datetime.now().isoformat(),
        "level":     level,
        "category":  category,
        "src_ip":    src_ip,
        "details":   details,
    }
    alert_history.append(alert)

    msg = f"{icon} [{level}] {category} — {src_ip} — {details}"
    if level == "HIGH":
        logger.warning(msg)
    else:
        logger.info(msg)

    # Save to JSON log
    with open(CONFIG["packet_log"], "a") as f:
        f.write(json.dumps(alert) + "\n")

    # Save to MySQL/MariaDB
    save_alert_to_db(level, category, src_ip, details)

# ─── Detection Engines ──────────────────────────────────────

def detect_port_scan(src_ip, dst_port):
    now       = time.time()
    window    = CONFIG["port_scan_window"]
    threshold = CONFIG["port_scan_threshold"]

    port_access[src_ip][dst_port].append(now)

    recent_ports = set()
    for port, times in port_access[src_ip].items():
        if any(now - t <= window for t in times):
            recent_ports.add(port)

    if len(recent_ports) >= threshold:
        fire_alert("HIGH", "PORT SCAN DETECTED", src_ip,
                   f"Hit {len(recent_ports)} unique ports in {window}s "
                   f"(last port: {dst_port})")
        port_access[src_ip].clear()


def detect_traffic_spike(src_ip):
    now       = time.time()
    window    = CONFIG["traffic_spike_window"]
    threshold = CONFIG["traffic_spike_threshold"]

    traffic_count[src_ip].append(now)
    traffic_count[src_ip] = [t for t in traffic_count[src_ip] if now - t <= window]

    rate = len(traffic_count[src_ip]) / window
    if rate >= threshold:
        fire_alert("HIGH", "TRAFFIC SPIKE / POSSIBLE DoS", src_ip,
                   f"{rate:.0f} packets/sec (threshold: {threshold})")
        traffic_count[src_ip].clear()


def detect_suspicious_ip(src_ip):
    if src_ip in CONFIG["suspicious_ips"]:
        fire_alert("HIGH", "KNOWN MALICIOUS IP", src_ip,
                   "IP found in blocklist")


def detect_suspicious_port(src_ip, dst_port):
    if dst_port in CONFIG["suspicious_ports"]:
        fire_alert("MEDIUM", "SUSPICIOUS PORT ACCESS", src_ip,
                   f"Attempted connection to high-risk port {dst_port}")


def detect_icmp_flood(src_ip, proto):
    if proto == "ICMP":
        now    = time.time()
        key    = f"ICMP:{src_ip}"
        traffic_count[key].append(now)
        recent = [t for t in traffic_count[key] if now - t <= 2]
        traffic_count[key] = recent
        if len(recent) > 50:
            fire_alert("MEDIUM", "ICMP FLOOD DETECTED", src_ip,
                       f"{len(recent)} ICMP packets in 2 seconds")
            traffic_count[key].clear()

# ─── Packet Processor ───────────────────────────────────────

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    proto    = "OTHER"
    dst_port = None

    if packet.haslayer(TCP):
        proto    = "TCP"
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto    = "UDP"
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto    = "ICMP"

    summary = (f"  [{proto}] {src_ip} → {dst_ip}"
               + (f":{dst_port}" if dst_port else ""))
    print(summary)

    # Save packet to DB
    save_packet_to_db(src_ip, dst_ip, proto, dst_port)

    # Run all detectors
    detect_suspicious_ip(src_ip)
    detect_traffic_spike(src_ip)
    detect_icmp_flood(src_ip, proto)

    if dst_port:
        detect_port_scan(src_ip, dst_port)
        detect_suspicious_port(src_ip, dst_port)

# ─── Simulation Mode ────────────────────────────────────────

def run_simulation():
    print("\n" + "═"*58)
    print("  🛡️  NIDS v2.0 — SIMULATION MODE + MySQL Logging")
    print("═"*58 + "\n")
    print("[SIM] Generating synthetic traffic events...\n")
    time.sleep(0.5)

    scenarios = [
        ("Normal web traffic",        "10.0.0.5",      80,   "TCP",  5,   0.2),
        ("Port scan from attacker",   "10.0.0.77",     None, "TCP",  20,  0.05),
        ("Known bad IP activity",     "192.168.1.100", 443,  "TCP",  3,   0.3),
        ("SSH brute force attempt",   "172.16.0.50",   22,   "TCP",  8,   0.1),
        ("Backdoor port probe",       "10.10.10.10",   4444, "TCP",  2,   0.5),
        ("ICMP flood",                "10.0.0.88",     None, "ICMP", 60,  0.02),
        ("DNS queries (normal)",      "10.0.0.3",      53,   "UDP",  4,   0.3),
        ("Traffic spike / DoS",       "10.0.0.99",     8080, "TCP",  250, 0.005),
        ("Telnet suspicious port",    "10.0.0.44",     23,   "TCP",  2,   0.5),
    ]

    for desc, src_ip, dst_port, proto, repeat, delay in scenarios:
        print(f"\n{'─'*55}")
        print(f"  📡 Scenario: {desc}")
        print(f"{'─'*55}")

        for i in range(repeat):
            port = dst_port if dst_port else (1024 + i * 7) % 65535

            # Save packet to DB
            save_packet_to_db(src_ip, "192.168.0.1", proto, port)

            print(f"  [{proto}] {src_ip} → 192.168.0.1:{port}")

            # Traffic spike
            now_t = time.time()
            traffic_count[src_ip].append(now_t)
            window = CONFIG["traffic_spike_window"]
            traffic_count[src_ip] = [t for t in traffic_count[src_ip] if now_t - t <= window]
            rate = len(traffic_count[src_ip]) / window
            if rate >= CONFIG["traffic_spike_threshold"]:
                fire_alert("HIGH", "TRAFFIC SPIKE / POSSIBLE DoS", src_ip,
                           f"{rate:.0f} pkt/s")
                traffic_count[src_ip].clear()

            # Suspicious IP
            if src_ip in CONFIG["suspicious_ips"]:
                fire_alert("HIGH", "KNOWN MALICIOUS IP", src_ip, "IP in blocklist")
                CONFIG["suspicious_ips"].remove(src_ip)

            # ICMP flood
            if proto == "ICMP":
                now_t2 = time.time()
                key = f"ICMP:{src_ip}"
                traffic_count[key].append(now_t2)
                recent = [t for t in traffic_count[key] if now_t2 - t <= 2]
                traffic_count[key] = recent
                if len(recent) > 50:
                    fire_alert("MEDIUM", "ICMP FLOOD DETECTED", src_ip,
                               f"{len(recent)} ICMP pkts in 2s")
                    traffic_count[key].clear()
            else:
                # Port scan
                now_t3 = time.time()
                port_access[src_ip][port].append(now_t3)
                recent_ports = {p for p, ts in port_access[src_ip].items()
                                if any(now_t3 - t <= CONFIG["port_scan_window"] for t in ts)}
                if len(recent_ports) >= CONFIG["port_scan_threshold"]:
                    fire_alert("HIGH", "PORT SCAN DETECTED", src_ip,
                               f"{len(recent_ports)} ports in {CONFIG['port_scan_window']}s")
                    port_access[src_ip].clear()

                if port in CONFIG["suspicious_ports"]:
                    fire_alert("MEDIUM", "SUSPICIOUS PORT ACCESS", src_ip,
                               f"Port {port}")

            time.sleep(delay)

    # ── Summary ──
    print("\n" + "═"*58)
    print(f"  ✅  Simulation complete — {len(alert_history)} alert(s) fired")
    print("═"*58)
    print("\n📋 ALERT SUMMARY:")
    for a in alert_history:
        lvl  = a['level']
        icon = "🔴" if lvl == "HIGH" else ("🟡" if lvl == "MEDIUM" else "🔵")
        print(f"  {icon} [{a['timestamp'][11:19]}] {a['category']} — {a['src_ip']}")

    print(f"\n  Log file  → nids_alerts.log")
    print(f"  JSON log  → packets.jsonl")
    print(f"  Database  → nids_db (alerts + packets tables)\n")

    # ── Verify DB records ──
    print("📊 Verifying database records...")
    conn = get_db()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM packets")
        packet_count = cursor.fetchone()[0]
        print(f"  ✅ alerts  table → {alert_count} records")
        print(f"  ✅ packets table → {packet_count} records")
        print("\n  Last 5 alerts from DB:")
        cursor.execute(
            "SELECT timestamp, level, category, src_ip FROM alerts ORDER BY id DESC LIMIT 5")
        for row in cursor.fetchall():
            icon = "🔴" if row[1] == "HIGH" else "🟡"
            print(f"  {icon} [{row[0]}] {row[2]} — {row[3]}")
        cursor.close()
        conn.close()

# ─── Live Sniffing Mode ─────────────────────────────────────

def run_live(interface=None, packet_count=0):
    iface_msg = f"on {interface}" if interface else "on default interface"
    count_msg = f"(capturing {packet_count} packets)" if packet_count else "(press Ctrl+C to stop)"

    print("\n" + "═"*58)
    print(f"  🛡️  NIDS v2.0 — LIVE MODE  {iface_msg}")
    print("═"*58)
    print(f"  {count_msg}")
    print("  Alerts → nids_alerts.log | DB → nids_db\n")

    kwargs = {"prn": process_packet, "store": False}
    if interface:
        kwargs["iface"] = interface
    if packet_count:
        kwargs["count"] = packet_count

    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        print("\n\n[*] Capture stopped by user.")
    finally:
        print(f"\n  📋 Total alerts fired: {len(alert_history)}")
        for a in alert_history:
            icon = "🔴" if a['level'] == "HIGH" else "🟡"
            print(f"  {icon} {a['category']} ← {a['src_ip']}")

# ─── Entry Point ────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System (NIDS) v2.0")
    parser.add_argument("-i", "--interface",
                        help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--simulate", action="store_true",
                        help="Run in simulation mode (no root required)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces")
    parser.add_argument("--show-db", action="store_true",
                        help="Show all alerts stored in database")
    args = parser.parse_args()

    print("""
  ╔══════════════════════════════════════════════════════╗
  ║      🛡️  NETWORK INTRUSION DETECTION SYSTEM          ║
  ║           Python + Scapy + MySQL  •  v2.0            ║
  ╚══════════════════════════════════════════════════════╝
    """)

    # Test DB connection on startup
    conn = get_db()
    if conn:
        print("  ✅ Database connected (nids_db)\n")
        conn.close()
    else:
        print("  ❌ Database connection failed — check MariaDB is running\n")

    if args.show_db:
        conn = get_db()
        if conn:
            cursor = conn.cursor()
            print("📊 All alerts in database:\n")
            cursor.execute(
                "SELECT timestamp, level, category, src_ip, details FROM alerts ORDER BY id DESC")
            rows = cursor.fetchall()
            if rows:
                for row in rows:
                    icon = "🔴" if row[1] == "HIGH" else "🟡"
                    print(f"  {icon} [{row[0]}] [{row[1]}] {row[2]} — {row[3]}")
                    print(f"       Details: {row[4]}")
            else:
                print("  No alerts found in database yet.")
            cursor.close()
            conn.close()
        return

    if args.list_interfaces:
        if SCAPY_AVAILABLE:
            print("Available interfaces:")
            for iface in get_if_list():
                print(f"  • {iface}")
        else:
            print("[!] Scapy not installed.")
        return

    if args.simulate or not SCAPY_AVAILABLE:
        run_simulation()
    else:
        run_live(interface=args.interface, packet_count=args.count)


if __name__ == "__main__":
    main()
