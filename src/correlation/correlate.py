"""
Event correlation module for AI SOC Analyst.
Groups related events into incidents based on patterns and time windows.
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

IN_PATH = Path("data/processed/normalized_events.jsonl")
OUT_PATH = Path("data/processed/incidents.jsonl")


def parse_ts(ts: str) -> datetime:
    """Parse ISO-8601 timestamp to datetime."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Read JSON Lines file into list of events."""
    events = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write incidents to JSON Lines file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def detect_signals(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a group of events and detect security signals/patterns.
    
    Returns:
        List of detected signals with metadata
    """
    signals = []
    
    # Count event types
    failures = [e for e in events if e.get("event_type") == "auth_failure"]
    successes = [e for e in events if e.get("event_type") == "auth_success"]
    fw_denies = [e for e in events if e.get("event_type") == "fw_deny"]
    suspicious_web = [e for e in events if e.get("event_type") == "web_access" 
                     and e.get("raw", {}).get("path") in {"/.env", "/backup.zip", "/admin", "/.git/config", "/wp-admin", "/phpMyAdmin", "/etc/passwd"}]
    process_events = [e for e in events if e.get("event_type") == "process_start"]
    suspicious_processes = [e for e in process_events 
                          if e.get("raw", {}).get("process_name", "").lower() in {"mimikatz.exe", "psexec.exe", "nc.exe", "whoami.exe", "net.exe"}]
    
    # Detect brute force pattern
    if len(failures) >= 10:
        signals.append({
            "signal": "possible_bruteforce",
            "count": len(failures),
            "description": f"Detected {len(failures)} failed authentication attempts"
        })
    
    # Detect successful compromise after brute force
    if len(failures) >= 10 and len(successes) >= 1:
        signals.append({
            "signal": "bruteforce_then_success",
            "count": len(successes),
            "description": f"Successful login detected after {len(failures)} failed attempts"
        })
    
    # Detect suspicious web access
    if len(suspicious_web) >= 1:
        paths = list(set(e.get("raw", {}).get("path") for e in suspicious_web))
        signals.append({
            "signal": "suspicious_web_paths",
            "count": len(suspicious_web),
            "paths": paths,
            "description": f"Access to sensitive paths: {', '.join(paths)}"
        })
    
    # Detect port scanning (multiple firewall denies from same source)
    if len(fw_denies) >= 5:
        ports = list(set(e.get("raw", {}).get("dst_port") for e in fw_denies if e.get("raw", {}).get("dst_port")))
        signals.append({
            "signal": "possible_port_scan",
            "count": len(fw_denies),
            "ports_targeted": len(ports),
            "description": f"Detected {len(fw_denies)} blocked connection attempts to {len(ports)} different ports"
        })
    
    # Detect suspicious process execution
    if len(suspicious_processes) >= 1:
        proc_names = list(set(e.get("raw", {}).get("process_name") for e in suspicious_processes))
        signals.append({
            "signal": "suspicious_process_execution",
            "count": len(suspicious_processes),
            "processes": proc_names,
            "description": f"Execution of known attack tools: {', '.join(proc_names)}"
        })
    
    # Detect lateral movement indicators
    if len(successes) >= 1 and len(suspicious_processes) >= 1:
        signals.append({
            "signal": "possible_lateral_movement",
            "count": len(suspicious_processes),
            "description": "Authentication followed by suspicious process execution"
        })
    
    return signals


def correlate_events(events: List[Dict[str, Any]], 
                    time_window_minutes: int = 60,
                    min_events: int = 5) -> List[Dict[str, Any]]:
    """
    Correlate events into incidents based on common attributes and time windows.
    
    Args:
        events: List of normalized events
        time_window_minutes: Maximum time span for grouping events
        min_events: Minimum number of events to form an incident
        
    Returns:
        List of incident objects
    """
    # Sort events by timestamp
    events.sort(key=lambda e: e.get("timestamp", ""))
    
    # Group by (host, user, src_ip) - the correlation key
    buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    
    for e in events:
        key = (
            e.get("host") or "unknown",
            e.get("user") or "unknown", 
            e.get("src_ip") or "unknown"
        )
        buckets[key].append(e)
    
    incidents = []
    
    for (host, user, src_ip), evts in buckets.items():
        # Skip groups with too few events
        if len(evts) < min_events:
            continue
        
        # Detect signals/patterns in this group
        signals = detect_signals(evts)
        
        # Only create incident if signals were detected
        if not signals:
            continue
        
        # Calculate time range
        timestamps = [parse_ts(e["timestamp"]) for e in evts if e.get("timestamp")]
        if not timestamps:
            continue
            
        start = min(timestamps)
        end = max(timestamps)
        
        # Generate incident ID
        incident_id = f"INC-{abs(hash((host, user, src_ip, start.isoformat()))) % 10_000_000:07d}"
        
        # Determine overall incident type
        signal_types = [s["signal"] for s in signals]
        if "bruteforce_then_success" in signal_types:
            incident_type = "Credential Compromise"
        elif "possible_bruteforce" in signal_types:
            incident_type = "Brute Force Attack"
        elif "suspicious_process_execution" in signal_types:
            incident_type = "Malicious Process Execution"
        elif "possible_port_scan" in signal_types:
            incident_type = "Port Scanning"
        elif "suspicious_web_paths" in signal_types:
            incident_type = "Web Application Attack"
        else:
            incident_type = "Suspicious Activity"
        
        incidents.append({
            "incident_id": incident_id,
            "incident_type": incident_type,
            "key": {
                "host": host,
                "user": user,
                "src_ip": src_ip
            },
            "time_range": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "duration_minutes": (end - start).total_seconds() / 60
            },
            "signals": signals,
            "event_count": len(evts),
            "events": evts
        })
    
    return incidents


def main():
    """Run correlation on normalized events."""
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading normalized events from {IN_PATH}...")
    events = read_jsonl(IN_PATH)
    
    print(f"Correlating {len(events)} events into incidents...")
    incidents = correlate_events(events)
    
    print(f"Writing {len(incidents)} incidents to {OUT_PATH}...")
    write_jsonl(OUT_PATH, incidents)
    
    # Print summary
    print("\nCorrelation Summary:")
    print(f"  Total events processed: {len(events)}")
    print(f"  Incidents generated: {len(incidents)}")
    
    for inc in incidents:
        print(f"\n  {inc['incident_id']} ({inc['incident_type']}):")
        print(f"    Key: host={inc['key']['host']}, user={inc['key']['user']}, src_ip={inc['key']['src_ip']}")
        print(f"    Events: {inc['event_count']}")
        print(f"    Signals: {[s['signal'] for s in inc['signals']]}")


if __name__ == "__main__":
    main()
