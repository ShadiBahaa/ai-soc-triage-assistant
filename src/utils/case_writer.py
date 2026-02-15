"""
Case file writer module for AI SOC Analyst.
Exports incident cases to JSON and Markdown formats.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

CASES_DIR = Path("docs/cases")


def write_case(
    incident: Dict[str, Any], 
    triage: Dict[str, Any], 
    summary: str,
    output_dir: Optional[Path] = None
) -> Dict[str, Path]:
    """
    Write incident case files (JSON and Markdown).
    
    Args:
        incident: The incident object with events and signals
        triage: The triage scoring result
        summary: Human-readable summary text
        output_dir: Optional custom output directory
        
    Returns:
        Dictionary with paths to created files
    """
    out_dir = output_dir or CASES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    
    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    
    # Prepare case object (excluding raw events to reduce file size)
    case = {
        "meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "version": "1.0",
            "tool": "AI SOC Triage Assistant"
        },
        "incident": {
            "incident_id": incident.get("incident_id"),
            "incident_type": incident.get("incident_type"),
            "key": incident.get("key"),
            "time_range": incident.get("time_range"),
            "signals": incident.get("signals"),
            "event_count": incident.get("event_count")
        },
        "triage": triage,
        "summary": summary
    }
    
    # Write JSON file
    json_path = out_dir / f"{incident_id}.json"
    json_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
    
    # Generate and write Markdown file
    md_content = generate_markdown(incident, triage, summary)
    md_path = out_dir / f"{incident_id}.md"
    md_path.write_text(md_content, encoding="utf-8")
    
    return {
        "json": json_path,
        "markdown": md_path
    }


def generate_markdown(incident: Dict[str, Any], triage: Dict[str, Any], summary: str) -> str:
    """
    Generate Markdown report for an incident.
    
    Args:
        incident: The incident object
        triage: The triage result
        summary: Human-readable summary
        
    Returns:
        Markdown formatted string
    """
    incident_id = incident.get("incident_id", "Unknown")
    incident_type = incident.get("incident_type", "Security Incident")
    key = incident.get("key", {})
    time_range = incident.get("time_range", {})
    signals = incident.get("signals", [])
    
    md = []
    
    # Title and metadata
    md.append(f"# {incident_id}")
    md.append("")
    md.append(f"> **Type:** {incident_type}  ")
    md.append(f"> **Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    md.append(f"> **Tool:** AI SOC Triage Assistant")
    md.append("")
    
    # Severity badge
    severity = triage.get("severity", "unknown")
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢"
    }.get(severity, "⚪")
    
    md.append(f"## Status: {severity_emoji} {severity.upper()}")
    md.append("")
    md.append(f"- **Confidence:** {triage.get('confidence', 0) * 100:.0f}%")
    md.append(f"- **Severity Score:** {triage.get('severity_score', 'N/A')}")
    if triage.get("requires_immediate_attention"):
        md.append("- **⚠️ REQUIRES IMMEDIATE ATTENTION**")
    md.append("")
    
    # Summary section
    md.append("## Summary")
    md.append("")
    md.append(summary)
    md.append("")
    
    # Affected Assets
    md.append("## Affected Assets")
    md.append("")
    md.append("| Attribute | Value |")
    md.append("|-----------|-------|")
    md.append(f"| Host | `{key.get('host', 'Unknown')}` |")
    md.append(f"| User | `{key.get('user', 'Unknown')}` |")
    md.append(f"| Source IP | `{key.get('src_ip', 'Unknown')}` |")
    md.append("")
    
    # Timeline
    md.append("## Timeline")
    md.append("")
    md.append(f"- **Start:** {time_range.get('start', 'Unknown')}")
    md.append(f"- **End:** {time_range.get('end', 'Unknown')}")
    md.append(f"- **Duration:** {time_range.get('duration_minutes', 0):.1f} minutes")
    md.append(f"- **Events:** {incident.get('event_count', 0)}")
    md.append("")
    
    # Signals Detected
    md.append("## Signals Detected")
    md.append("")
    for signal in signals:
        md.append(f"### {signal.get('signal', 'unknown')}")
        md.append(f"- **Count:** {signal.get('count', 0)}")
        if signal.get('description'):
            md.append(f"- **Description:** {signal.get('description')}")
        if signal.get('paths'):
            md.append(f"- **Paths:** {', '.join(signal.get('paths', []))}")
        if signal.get('processes'):
            md.append(f"- **Processes:** {', '.join(signal.get('processes', []))}")
        md.append("")
    
    # MITRE ATT&CK Mapping
    if triage.get("mitre"):
        md.append("## MITRE ATT&CK Mapping")
        md.append("")
        md.append("| Technique | Name | Tactic |")
        md.append("|-----------|------|--------|")
        for m in triage["mitre"]:
            technique = m.get("technique", "")
            name = m.get("technique_name", "")
            tactic = m.get("tactic", "")
            url = m.get("url", f"https://attack.mitre.org/techniques/{technique}/")
            md.append(f"| [{technique}]({url}) | {name} | {tactic} |")
        md.append("")
    
    # Recommended Actions
    if triage.get("recommended_actions"):
        md.append("## Recommended Actions")
        md.append("")
        for i, action in enumerate(triage["recommended_actions"], 1):
            md.append(f"{i}. {action}")
        md.append("")
    
    # Triage Details (collapsed)
    md.append("## Triage Details")
    md.append("")
    md.append("<details>")
    md.append("<summary>Click to expand triage JSON</summary>")
    md.append("")
    md.append("```json")
    md.append(json.dumps(triage, indent=2))
    md.append("```")
    md.append("")
    md.append("</details>")
    md.append("")
    
    # Incident Key Details (collapsed)
    md.append("## Incident Key")
    md.append("")
    md.append("<details>")
    md.append("<summary>Click to expand incident key JSON</summary>")
    md.append("")
    md.append("```json")
    md.append(json.dumps(key, indent=2))
    md.append("```")
    md.append("")
    md.append("</details>")
    md.append("")
    
    # Signals Details (collapsed)
    md.append("## Signals Data")
    md.append("")
    md.append("<details>")
    md.append("<summary>Click to expand signals JSON</summary>")
    md.append("")
    md.append("```json")
    md.append(json.dumps(signals, indent=2))
    md.append("```")
    md.append("")
    md.append("</details>")
    md.append("")
    
    # Footer
    md.append("---")
    md.append("*This report was automatically generated by AI SOC Triage Assistant.*")
    
    return "\n".join(md)


def write_executive_summary(
    incidents: list,
    total_events: int,
    output_dir: Optional[Path] = None
) -> Path:
    """
    Write an executive summary of all incidents.
    
    Args:
        incidents: List of processed incidents with triage
        total_events: Total events analyzed
        output_dir: Optional custom output directory
        
    Returns:
        Path to created summary file
    """
    out_dir = output_dir or CASES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Calculate statistics
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        sev = inc.get("triage", {}).get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    md = []
    md.append("# Executive Security Summary")
    md.append("")
    md.append(f"> **Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md.append("")
    
    md.append("## Overview")
    md.append("")
    md.append(f"- **Total Events Analyzed:** {total_events:,}")
    md.append(f"- **Incidents Identified:** {len(incidents)}")
    md.append("")
    
    md.append("## Severity Distribution")
    md.append("")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    md.append(f"| 🔴 Critical | {severity_counts['critical']} |")
    md.append(f"| 🟠 High | {severity_counts['high']} |")
    md.append(f"| 🟡 Medium | {severity_counts['medium']} |")
    md.append(f"| 🟢 Low | {severity_counts['low']} |")
    md.append("")
    
    md.append("## Incidents")
    md.append("")
    for inc in incidents:
        inc_id = inc.get("incident_id", "Unknown")
        inc_type = inc.get("incident_type", "Unknown")
        severity = inc.get("triage", {}).get("severity", "unknown")
        key = inc.get("key", {})
        
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        md.append(f"### {emoji} [{inc_id}](./{inc_id}.md)")
        md.append(f"- **Type:** {inc_type}")
        md.append(f"- **Severity:** {severity.upper()}")
        md.append(f"- **Host:** {key.get('host', 'Unknown')}")
        md.append(f"- **User:** {key.get('user', 'Unknown')}")
        md.append(f"- **Source IP:** {key.get('src_ip', 'Unknown')}")
        md.append("")
    
    md.append("---")
    md.append("*Generated by AI SOC Triage Assistant*")
    
    summary_path = out_dir / "SUMMARY.md"
    summary_path.write_text("\n".join(md), encoding="utf-8")
    
    return summary_path
