"""
Log normalization module for AI SOC Analyst.
Converts raw logs from various sources into a common schema.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

IN_PATH = Path("data/raw/sample_logs.jsonl")
OUT_PATH = Path("data/processed/normalized_events.jsonl")


# External/suspicious IP prefixes (simplified for demo)
EXTERNAL_IP_PREFIXES = ("198.", "203.", "192.0.2.", "45.", "185.")


def is_external_ip(ip: Optional[str]) -> bool:
    """Check if an IP address appears to be external/suspicious."""
    if not ip:
        return False
    return ip.startswith(EXTERNAL_IP_PREFIXES)


def severity_from_event(evt: Dict[str, Any]) -> Optional[str]:
    """
    Determine preliminary severity based on event characteristics.
    
    Returns:
        Severity level: 'low', 'medium', 'high', 'critical', or None
    """
    event_type = evt.get("event_type", "")
    source = evt.get("source", "")
    src_ip = evt.get("src_ip", "")
    path = evt.get("path", "")
    action = evt.get("action", "")
    process_name = evt.get("process_name", "")
    
    # High severity indicators
    high_severity_paths = {"/.env", "/backup.zip", "/.git/config", "/etc/passwd", "/wp-admin/admin-ajax.php"}
    suspicious_processes = {"mimikatz.exe", "psexec.exe", "nc.exe", "procdump.exe"}
    
    # Critical: Known malicious tools
    if process_name.lower() in suspicious_processes:
        return "critical"
    
    # High: Successful auth from external IP after failures
    if event_type == "auth_success" and is_external_ip(src_ip):
        return "high"
    
    # High: Access to sensitive paths
    if event_type == "web_access" and path in high_severity_paths:
        return "high"
    
    # Medium: Auth failures (potential brute force)
    if event_type == "auth_failure":
        return "medium"
    
    # Medium: Firewall denies from external
    if event_type == "fw_deny" and is_external_ip(src_ip):
        return "medium"
    
    # Low: Suspicious but less concerning
    if event_type == "web_access" and path in {"/admin", "/phpMyAdmin"}:
        return "low"
    
    return None


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw log event into the common schema.
    
    Args:
        raw: Raw event dictionary from any supported source
        
    Returns:
        Normalized event dictionary
    """
    source = raw.get("source", "other")
    
    # Extract action based on source type
    if source == "web":
        action = raw.get("path")
    elif source == "endpoint":
        action = raw.get("command_line") or raw.get("process_name")
    elif source == "fw":
        action = raw.get("action")
    else:
        action = raw.get("message")
    
    return {
        "timestamp": raw.get("timestamp"),
        "source": source,
        "host": raw.get("host"),
        "user": raw.get("user"),
        "src_ip": raw.get("src_ip"),
        "dst_ip": raw.get("dst_ip"),
        "event_type": raw.get("event_type", "unknown"),
        "action": action,
        "status": raw.get("status"),
        "severity_hint": severity_from_event(raw),
        "raw": raw
    }


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    """Read JSON Lines file and yield events."""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write events to JSON Lines file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def main():
    """Run normalization on sample logs."""
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading raw logs from {IN_PATH}...")
    rows = [normalize(r) for r in read_jsonl(IN_PATH)]
    
    # Sort by timestamp
    rows.sort(key=lambda x: x.get("timestamp", ""))
    
    print(f"Writing {len(rows)} normalized events to {OUT_PATH}...")
    write_jsonl(OUT_PATH, rows)
    
    # Print summary statistics
    severity_counts = {}
    source_counts = {}
    for r in rows:
        sev = r.get("severity_hint") or "none"
        src = r.get("source", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1
    
    print("\nNormalization Summary:")
    print(f"  Total events: {len(rows)}")
    print(f"  By source: {source_counts}")
    print(f"  By severity: {severity_counts}")


if __name__ == "__main__":
    main()
