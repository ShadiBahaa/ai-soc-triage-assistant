"""
LLM prompt templates for AI SOC Analyst.
Defines prompts for incident summarization and analysis.
"""

import json
from typing import Any, Dict


def incident_prompt(incident: Dict[str, Any], triage: Dict[str, Any]) -> str:
    """
    Generate a prompt for LLM-based incident summarization.
    
    Args:
        incident: The incident object with events and signals
        triage: The triage scoring result
        
    Returns:
        Formatted prompt string for the LLM
    """
    # Prepare a condensed view of the incident (exclude raw events to reduce tokens)
    incident_summary = {
        "incident_id": incident.get("incident_id"),
        "incident_type": incident.get("incident_type"),
        "key": incident.get("key"),
        "time_range": incident.get("time_range"),
        "signals": incident.get("signals"),
        "event_count": incident.get("event_count")
    }
    
    return f"""You are an expert SOC (Security Operations Center) analyst. 
Analyze the following security incident and provide a comprehensive summary.

Your summary should include:
1. **What happened**: A clear description of the security event
2. **Why it matters**: The potential impact and risk to the organization
3. **Most likely scenario**: Your assessment of what the attacker was trying to achieve
4. **Immediate next steps**: Concrete actions the SOC should take right now
5. **What to verify**: Additional investigation points to confirm the analysis

Keep the summary professional, actionable, and suitable for both technical staff and management.
Return plain text only, using markdown formatting for readability.

=== INCIDENT DATA ===
{json.dumps(incident_summary, indent=2)}

=== TRIAGE ASSESSMENT ===
Severity: {triage.get('severity', 'unknown')}
Confidence: {triage.get('confidence', 0) * 100:.0f}%
MITRE Techniques: {', '.join(m['technique'] + ' (' + m['technique_name'] + ')' for m in triage.get('mitre', []))}

=== RECOMMENDED ACTIONS ===
{chr(10).join('- ' + a for a in triage.get('recommended_actions', []))}

Please provide your analysis:""".strip()


def executive_summary_prompt(incidents: list, total_events: int) -> str:
    """
    Generate a prompt for executive-level summary of multiple incidents.
    
    Args:
        incidents: List of incidents with their triage results
        total_events: Total number of events processed
        
    Returns:
        Formatted prompt for executive summary
    """
    # Summarize incidents by severity
    severity_counts = {}
    for inc in incidents:
        sev = inc.get("triage", {}).get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    incident_summaries = []
    for inc in incidents[:10]:  # Limit to top 10 for brevity
        incident_summaries.append({
            "id": inc.get("incident_id"),
            "type": inc.get("incident_type"),
            "severity": inc.get("triage", {}).get("severity"),
            "host": inc.get("key", {}).get("host"),
            "signals": [s.get("signal") for s in inc.get("signals", [])]
        })
    
    return f"""You are preparing an executive briefing on the security posture based on recent log analysis.

Summary Statistics:
- Total events analyzed: {total_events}
- Incidents identified: {len(incidents)}
- By severity: {json.dumps(severity_counts)}

Top Incidents:
{json.dumps(incident_summaries, indent=2)}

Please provide:
1. A 2-3 sentence executive summary of the security situation
2. The most critical risk requiring attention
3. Overall security posture assessment (good/concerning/critical)
4. Key recommendation for leadership

Keep the summary non-technical and focused on business impact.""".strip()


def threat_intel_prompt(incident: Dict[str, Any]) -> str:
    """
    Generate a prompt for threat intelligence enrichment.
    
    Args:
        incident: The incident object
        
    Returns:
        Formatted prompt for threat intel analysis
    """
    key = incident.get("key", {})
    signals = incident.get("signals", [])
    
    return f"""As a threat intelligence analyst, analyze this incident and provide context:

Source IP: {key.get('src_ip', 'Unknown')}
Target Host: {key.get('host', 'Unknown')}
Target User: {key.get('user', 'Unknown')}
Detected Signals: {', '.join(s.get('signal') for s in signals)}

Please provide:
1. Known threat actor patterns that match this behavior
2. Similar attack campaigns from threat intel feeds
3. Indicators of Compromise (IOCs) to look for
4. Potential attribution (nation-state, criminal, opportunistic)
5. Recommended threat hunting queries

Note: Base your analysis only on the patterns observed, not on actual threat intel lookups.""".strip()
