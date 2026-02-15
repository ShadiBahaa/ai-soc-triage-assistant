"""
Incident triage scoring module for AI SOC Analyst.
Calculates severity, confidence, and recommended actions based on detected signals.
"""

from typing import Any, Dict, List
from .mitre_mapping import MITRE_MAP, get_mitre_info, get_mitre_url


def score_incident(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate triage score for an incident based on its signals.
    
    Args:
        signals: List of detected signals from correlation
        
    Returns:
        Triage result with severity, confidence, MITRE mapping, and recommendations
    """
    mitre_mappings = []
    total_score = 0
    
    # Process each signal and accumulate scores
    for signal in signals:
        signal_name = signal.get("signal", "unknown")
        mitre_info = get_mitre_info(signal_name)
        
        # Add to total severity score
        weight = mitre_info.get("severity_weight", 1)
        count = signal.get("count", 1)
        
        # Scale weight by count (with diminishing returns)
        if count > 10:
            weight_multiplier = 1.5
        elif count > 5:
            weight_multiplier = 1.2
        else:
            weight_multiplier = 1.0
        
        total_score += weight * weight_multiplier
        
        # Build MITRE mapping entry
        mitre_mappings.append({
            "signal": signal_name,
            "technique": mitre_info["technique"],
            "technique_name": mitre_info["technique_name"],
            "tactic": mitre_info["tactic"],
            "url": get_mitre_url(mitre_info["technique"]),
            "description": mitre_info["description"]
        })
    
    # Determine severity level
    if total_score >= 10:
        severity = "critical"
    elif total_score >= 6:
        severity = "high"
    elif total_score >= 3:
        severity = "medium"
    else:
        severity = "low"
    
    # Calculate confidence (based on signal strength and count)
    base_confidence = 0.5
    confidence_boost = min(0.45, 0.08 * total_score)
    confidence = round(base_confidence + confidence_boost, 2)
    
    # Generate recommended actions based on detected techniques
    recommended_actions = generate_recommendations(mitre_mappings, signals)
    
    return {
        "severity": severity,
        "severity_score": round(total_score, 2),
        "confidence": confidence,
        "mitre": mitre_mappings,
        "recommended_actions": recommended_actions,
        "requires_immediate_attention": severity in ["critical", "high"]
    }


def generate_recommendations(mitre_mappings: List[Dict], signals: List[Dict]) -> List[str]:
    """
    Generate recommended next actions based on detected techniques.
    
    Args:
        mitre_mappings: List of mapped MITRE techniques
        signals: Original signal list
        
    Returns:
        List of recommended actions
    """
    actions = []
    techniques = {m["technique"] for m in mitre_mappings}
    signal_names = {s["signal"] for s in signals}
    
    # Brute Force (T1110)
    if "T1110" in techniques:
        actions.extend([
            "🔐 Check account lockout and MFA status for impacted user",
            "🔍 Review authentication logs for the same source IP across other users",
            "🚫 Consider blocking or rate-limiting the suspicious source IP at the edge",
            "📧 Notify the affected user and verify recent login activity"
        ])
    
    # Exploit Public-Facing App (T1190)
    if "T1190" in techniques:
        actions.extend([
            "🌐 Inspect web server logs for suspicious requests and payloads",
            "🔒 Validate that sensitive files (.env, backups) are not publicly accessible",
            "🔄 Rotate any potentially leaked secrets or API keys",
            "📋 Review web application firewall (WAF) rules and consider blocking patterns"
        ])
    
    # Network Service Discovery (T1046)
    if "T1046" in techniques:
        actions.extend([
            "🔎 Review firewall logs for the source IP across all network segments",
            "🛡️ Verify no services were exposed that shouldn't be",
            "📝 Document the scanning pattern for threat intelligence"
        ])
    
    # Command and Scripting Interpreter (T1059)
    if "T1059" in techniques:
        actions.extend([
            "💻 Review process execution history on the affected host",
            "🔬 Collect and analyze any suspicious executables",
            "🧹 Run malware scan on the affected endpoint",
            "📸 Capture memory dump if active compromise suspected"
        ])
    
    # Lateral Movement (T1021)
    if "T1021" in techniques:
        actions.extend([
            "🗺️ Map all systems accessed by the compromised credentials",
            "🔑 Force password reset for affected accounts",
            "🔌 Consider isolating affected systems from network",
            "📊 Review authentication logs across all critical systems"
        ])
    
    # Credential Dumping (T1003)
    if "T1003" in techniques:
        actions.extend([
            "🚨 URGENT: Assume all credentials on the system are compromised",
            "🔄 Rotate all service account passwords and certificates",
            "🔍 Check for persistence mechanisms (scheduled tasks, services)",
            "📞 Escalate to incident response team immediately"
        ])
    
    # If bruteforce was successful
    if "bruteforce_then_success" in signal_names:
        actions.insert(0, "⚠️ PRIORITY: Credential compromise confirmed - immediate containment required")
    
    # If suspicious processes detected
    if "suspicious_process_execution" in signal_names:
        actions.insert(0, "🔴 CRITICAL: Malicious tool execution detected - consider host isolation")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_actions = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            unique_actions.append(action)
    
    return unique_actions
