"""
Incident summarization module for AI SOC Analyst.
Generates human-readable summaries of security incidents.
"""

from typing import Any, Dict
from datetime import datetime


def summarize_incident(incident: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """
    Generate a plain-English summary of an incident.
    
    This is the deterministic summarizer that works without an LLM.
    
    Args:
        incident: The incident object with events and signals
        triage: The triage scoring result
        
    Returns:
        Human-readable incident summary
    """
    key = incident.get("key", {})
    signals = incident.get("signals", [])
    time_range = incident.get("time_range", {})
    incident_type = incident.get("incident_type", "Security Incident")
    event_count = incident.get("event_count", 0)
    
    lines = []
    
    # Header
    lines.append(f"## Incident Summary: {incident['incident_id']}")
    lines.append("")
    
    # Classification
    lines.append(f"**Type:** {incident_type}")
    lines.append(f"**Severity:** {triage['severity'].upper()} (score: {triage.get('severity_score', 'N/A')})")
    lines.append(f"**Confidence:** {triage['confidence']*100:.0f}%")
    if triage.get('requires_immediate_attention'):
        lines.append("**⚠️ REQUIRES IMMEDIATE ATTENTION**")
    lines.append("")
    
    # Affected Assets
    lines.append("### Affected Assets")
    lines.append(f"- **Host:** {key.get('host', 'Unknown')}")
    lines.append(f"- **User:** {key.get('user', 'Unknown')}")
    lines.append(f"- **Source IP:** {key.get('src_ip', 'Unknown')}")
    lines.append("")
    
    # Timeline
    lines.append("### Timeline")
    start = time_range.get('start', 'Unknown')
    end = time_range.get('end', 'Unknown')
    duration = time_range.get('duration_minutes', 0)
    lines.append(f"- **Start:** {start}")
    lines.append(f"- **End:** {end}")
    lines.append(f"- **Duration:** {duration:.1f} minutes")
    lines.append(f"- **Total Events:** {event_count}")
    lines.append("")
    
    # What Happened
    lines.append("### What Happened")
    for signal in signals:
        signal_name = signal.get('signal', 'unknown')
        description = signal.get('description', f"Detected {signal_name}")
        count = signal.get('count', 0)
        lines.append(f"- {description}")
    lines.append("")
    
    # Attack Narrative
    lines.append("### Attack Narrative")
    narrative = generate_narrative(incident, triage)
    lines.append(narrative)
    lines.append("")
    
    # MITRE ATT&CK Mapping
    if triage.get('mitre'):
        lines.append("### MITRE ATT&CK Mapping")
        for m in triage['mitre']:
            lines.append(f"- **{m['technique']}** - {m['technique_name']} ({m['tactic']})")
            lines.append(f"  - {m['description']}")
        lines.append("")
    
    # Recommended Actions
    if triage.get('recommended_actions'):
        lines.append("### Recommended Actions")
        for i, action in enumerate(triage['recommended_actions'], 1):
            lines.append(f"{i}. {action}")
        lines.append("")
    
    return "\n".join(lines)


def generate_narrative(incident: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """
    Generate a narrative description of what likely happened.
    
    Args:
        incident: The incident object
        triage: The triage result
        
    Returns:
        Narrative string
    """
    key = incident.get("key", {})
    signals = incident.get("signals", [])
    signal_names = [s.get("signal") for s in signals]
    
    host = key.get('host', 'a system')
    user = key.get('user', 'a user account')
    src_ip = key.get('src_ip', 'an external IP')
    
    narrative_parts = []
    
    # Build narrative based on detected signals
    if "possible_bruteforce" in signal_names:
        failure_count = next((s.get('count', 0) for s in signals if s['signal'] == 'possible_bruteforce'), 0)
        narrative_parts.append(
            f"An attacker from {src_ip} attempted to gain access to the account '{user}' on {host} "
            f"through brute force, generating {failure_count} failed login attempts."
        )
    
    if "bruteforce_then_success" in signal_names:
        narrative_parts.append(
            f"The brute force attack was successful. The attacker gained valid credentials "
            f"and authenticated to the system. This represents a confirmed credential compromise."
        )
    
    if "suspicious_web_paths" in signal_names:
        paths_signal = next((s for s in signals if s['signal'] == 'suspicious_web_paths'), {})
        paths = paths_signal.get('paths', [])
        narrative_parts.append(
            f"Following initial access, suspicious web requests were observed targeting "
            f"sensitive paths ({', '.join(paths)}), suggesting reconnaissance or data exfiltration attempts."
        )
    
    if "possible_port_scan" in signal_names:
        scan_signal = next((s for s in signals if s['signal'] == 'possible_port_scan'), {})
        port_count = scan_signal.get('ports_targeted', 0)
        narrative_parts.append(
            f"Network scanning activity was detected from {src_ip}, probing {port_count} different "
            f"ports. This suggests reconnaissance activity to identify exploitable services."
        )
    
    if "suspicious_process_execution" in signal_names:
        proc_signal = next((s for s in signals if s['signal'] == 'suspicious_process_execution'), {})
        processes = proc_signal.get('processes', [])
        narrative_parts.append(
            f"Suspicious processes were executed on {host}: {', '.join(processes)}. "
            f"These are known attack tools commonly used for credential theft or lateral movement."
        )
    
    if "possible_lateral_movement" in signal_names:
        narrative_parts.append(
            f"The combination of successful authentication and suspicious process execution "
            f"suggests the attacker may be attempting to move laterally through the network."
        )
    
    # Combine narrative parts
    if narrative_parts:
        return " ".join(narrative_parts)
    else:
        return (
            f"Suspicious activity was detected involving host {host}, user {user}, "
            f"and source IP {src_ip}. The activity pattern warrants further investigation."
        )


def format_summary_short(incident: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """
    Generate a short one-line summary for dashboards/listings.
    
    Args:
        incident: The incident object
        triage: The triage result
        
    Returns:
        Short summary string
    """
    severity = triage.get('severity', 'unknown').upper()
    incident_type = incident.get('incident_type', 'Incident')
    key = incident.get('key', {})
    
    return f"[{severity}] {incident_type} - {key.get('host', '?')} / {key.get('user', '?')} from {key.get('src_ip', '?')}"
