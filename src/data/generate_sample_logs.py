"""
Sample log generator for AI SOC Analyst.
Generates synthetic but realistic security logs for testing the pipeline.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path("data/raw/sample_logs.jsonl")
OUT.parent.mkdir(parents=True, exist_ok=True)

USERS = ["alice", "bob", "carol", "dave", "admin", "svc_backup", "deploy_bot"]
HOSTS = ["wkst-01", "wkst-02", "wkst-03", "srv-web-01", "srv-db-01", "srv-app-01", "fw-edge-01"]
INTERNAL_IPS = ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.2.20", "10.0.2.21", "10.0.9.99"]
EXTERNAL_IPS = ["198.51.100.10", "203.0.113.55", "192.0.2.77", "45.33.32.156", "185.220.101.42"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Wget/1.21.3"
]

BENIGN_PATHS = ["/", "/index.html", "/api/status", "/api/users", "/dashboard", "/login", "/logout"]
SUSPICIOUS_PATHS = ["/.env", "/backup.zip", "/admin", "/wp-admin", "/phpMyAdmin", "/.git/config", "/etc/passwd"]
PROCESSES = ["chrome.exe", "explorer.exe", "svchost.exe", "notepad.exe", "powershell.exe", "cmd.exe"]
SUSPICIOUS_PROCESSES = ["mimikatz.exe", "psexec.exe", "nc.exe", "whoami.exe", "net.exe"]


def ts(base: datetime, minutes: int) -> str:
    """Generate ISO-8601 timestamp."""
    return (base + timedelta(minutes=minutes)).isoformat() + "Z"


def generate_auth_log(base: datetime, minute: int, is_malicious: bool = False, 
                      attacker_ip: str = None, target_user: str = None, target_host: str = None) -> dict:
    """Generate authentication log event."""
    if is_malicious:
        return {
            "source": "auth",
            "timestamp": ts(base, minute),
            "host": target_host or random.choice(HOSTS),
            "user": target_user or random.choice(USERS),
            "src_ip": attacker_ip or random.choice(EXTERNAL_IPS),
            "dst_ip": random.choice(INTERNAL_IPS),
            "message": "Failed login attempt" if random.random() > 0.1 else "Successful login",
            "event_type": "auth_failure" if random.random() > 0.1 else "auth_success",
            "status": "failure" if random.random() > 0.1 else "success",
            "auth_method": random.choice(["password", "kerberos", "ntlm"]),
            "logon_type": random.choice([2, 3, 10])  # Interactive, Network, RemoteInteractive
        }
    else:
        return {
            "source": "auth",
            "timestamp": ts(base, minute),
            "host": random.choice(HOSTS),
            "user": random.choice(USERS),
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": random.choice(INTERNAL_IPS),
            "message": "Successful login",
            "event_type": "auth_success",
            "status": "success",
            "auth_method": random.choice(["password", "kerberos", "ntlm"]),
            "logon_type": random.choice([2, 3, 10])
        }


def generate_web_log(base: datetime, minute: int, is_malicious: bool = False,
                     attacker_ip: str = None, target_host: str = None) -> dict:
    """Generate web access log event."""
    if is_malicious:
        path = random.choice(SUSPICIOUS_PATHS)
        status_code = random.choice([200, 401, 403, 404, 500])
    else:
        path = random.choice(BENIGN_PATHS)
        status_code = random.choice([200, 200, 200, 301, 304])
    
    return {
        "source": "web",
        "timestamp": ts(base, minute),
        "host": target_host or random.choice([h for h in HOSTS if "web" in h or "app" in h]),
        "user": "-",
        "src_ip": attacker_ip if is_malicious else random.choice(INTERNAL_IPS + EXTERNAL_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "http_method": random.choice(["GET", "POST", "PUT", "DELETE"]) if is_malicious else "GET",
        "path": path,
        "status_code": status_code,
        "bytes_sent": random.randint(100, 50000),
        "user_agent": random.choice(USER_AGENTS),
        "message": "web request",
        "event_type": "web_access",
        "status": "info"
    }


def generate_firewall_log(base: datetime, minute: int, is_malicious: bool = False,
                          attacker_ip: str = None) -> dict:
    """Generate firewall log event."""
    if is_malicious:
        action = random.choice(["deny", "deny", "allow"])
        port = random.choice([22, 23, 3389, 445, 135, 1433, 3306])
    else:
        action = random.choice(["allow", "allow", "allow", "deny"])
        port = random.choice([80, 443, 53, 123, 22])
    
    return {
        "source": "fw",
        "timestamp": ts(base, minute),
        "host": "fw-edge-01",
        "user": None,
        "src_ip": attacker_ip if is_malicious else random.choice(INTERNAL_IPS + EXTERNAL_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "src_port": random.randint(1024, 65535),
        "dst_port": port,
        "protocol": random.choice(["TCP", "UDP"]),
        "action": action,
        "message": f"Firewall {action} connection",
        "event_type": f"fw_{action}",
        "status": "info",
        "bytes": random.randint(0, 10000) if action == "allow" else 0
    }


def generate_endpoint_log(base: datetime, minute: int, is_malicious: bool = False,
                          target_host: str = None, target_user: str = None) -> dict:
    """Generate endpoint process execution log."""
    if is_malicious:
        process = random.choice(SUSPICIOUS_PROCESSES)
        parent = random.choice(["cmd.exe", "powershell.exe", "explorer.exe"])
    else:
        process = random.choice(PROCESSES)
        parent = random.choice(["explorer.exe", "services.exe", "svchost.exe"])
    
    return {
        "source": "endpoint",
        "timestamp": ts(base, minute),
        "host": target_host or random.choice(HOSTS),
        "user": target_user or random.choice(USERS),
        "src_ip": None,
        "dst_ip": None,
        "process_name": process,
        "process_id": random.randint(1000, 65535),
        "parent_process": parent,
        "command_line": f"C:\\Windows\\System32\\{process}" + (" -enc base64data" if is_malicious else ""),
        "message": f"Process execution: {process}",
        "event_type": "process_start",
        "status": "info"
    }


def main():
    """Generate sample logs with both benign and malicious activity."""
    base = datetime.utcnow() - timedelta(days=1)
    rows = []

    # === BENIGN BACKGROUND ACTIVITY ===
    print("Generating benign background activity...")
    for i in range(200):
        source = random.choice(["auth", "web", "fw", "endpoint"])
        if source == "auth":
            rows.append(generate_auth_log(base, i))
        elif source == "web":
            rows.append(generate_web_log(base, i))
        elif source == "fw":
            rows.append(generate_firewall_log(base, i))
        else:
            rows.append(generate_endpoint_log(base, i))

    # === ATTACK SCENARIO 1: BRUTE FORCE + COMPROMISE ===
    print("Generating brute force attack scenario...")
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_user = "alice"
    target_host = "srv-web-01"
    
    # Phase 1: Brute force attempts (30 failed logins)
    for i in range(30):
        evt = generate_auth_log(base, 300 + i, is_malicious=True, 
                               attacker_ip=attacker_ip, target_user=target_user, target_host=target_host)
        evt["event_type"] = "auth_failure"
        evt["status"] = "failure"
        evt["message"] = "Failed login attempt"
        rows.append(evt)

    # Phase 2: Successful login
    success_evt = generate_auth_log(base, 340, is_malicious=True,
                                   attacker_ip=attacker_ip, target_user=target_user, target_host=target_host)
    success_evt["event_type"] = "auth_success"
    success_evt["status"] = "success"
    success_evt["message"] = "Successful login"
    rows.append(success_evt)

    # Phase 3: Suspicious web activity after compromise
    for i in range(5):
        rows.append(generate_web_log(base, 345 + i, is_malicious=True,
                                    attacker_ip=attacker_ip, target_host=target_host))

    # === ATTACK SCENARIO 2: PORT SCANNING ===
    print("Generating port scanning scenario...")
    scanner_ip = "185.220.101.42"
    for i in range(20):
        evt = generate_firewall_log(base, 400 + i, is_malicious=True, attacker_ip=scanner_ip)
        evt["dst_port"] = 22 + i * 100  # Scanning different ports
        rows.append(evt)

    # === ATTACK SCENARIO 3: SUSPICIOUS ENDPOINT ACTIVITY ===
    print("Generating suspicious endpoint activity...")
    compromised_host = "wkst-02"
    compromised_user = "bob"
    for i in range(3):
        rows.append(generate_endpoint_log(base, 500 + i * 2, is_malicious=True,
                                         target_host=compromised_host, target_user=compromised_user))

    # Shuffle to mix events realistically
    random.shuffle(rows)

    # Write to file
    print(f"Writing {len(rows)} events to {OUT}...")
    with OUT.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(rows)} log entries in {OUT}")


if __name__ == "__main__":
    main()
