"""
MITRE ATT&CK mapping for detected security signals.
Maps internal signal names to MITRE techniques for standardized reporting.
"""

MITRE_MAP = {
    # Credential Access
    "possible_bruteforce": {
        "technique": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "severity_weight": 2,
        "description": "Adversaries may use brute force techniques to guess credentials."
    },
    "bruteforce_then_success": {
        "technique": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "severity_weight": 4,
        "description": "Successful credential compromise following brute force attempts."
    },
    
    # Initial Access
    "suspicious_web_paths": {
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity_weight": 3,
        "description": "Adversaries may exploit vulnerabilities in public-facing applications."
    },
    
    # Discovery / Reconnaissance
    "possible_port_scan": {
        "technique": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity_weight": 2,
        "description": "Adversaries may scan for network services to identify targets."
    },
    
    # Execution
    "suspicious_process_execution": {
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity_weight": 4,
        "description": "Adversaries may abuse command interpreters to execute commands."
    },
    
    # Lateral Movement
    "possible_lateral_movement": {
        "technique": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "severity_weight": 4,
        "description": "Adversaries may use valid accounts to log into remote services."
    },
    
    # Credential Dumping (specific tools)
    "mimikatz_detected": {
        "technique": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "severity_weight": 5,
        "description": "Adversaries may dump credentials to obtain account login information."
    },
    
    # Exfiltration indicators
    "data_exfiltration_attempt": {
        "technique": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "severity_weight": 4,
        "description": "Adversaries may steal data by exfiltrating it over the command and control channel."
    },
    
    # Default/unknown
    "unknown_suspicious_activity": {
        "technique": "T1199",
        "technique_name": "Trusted Relationship",
        "tactic": "Initial Access",
        "severity_weight": 1,
        "description": "Suspicious activity that requires further investigation."
    }
}


def get_mitre_info(signal_name: str) -> dict:
    """
    Get MITRE ATT&CK information for a given signal.
    
    Args:
        signal_name: Internal signal identifier
        
    Returns:
        MITRE mapping dictionary or default unknown mapping
    """
    return MITRE_MAP.get(signal_name, MITRE_MAP["unknown_suspicious_activity"])


def get_mitre_url(technique_id: str) -> str:
    """
    Generate MITRE ATT&CK URL for a technique.
    
    Args:
        technique_id: MITRE technique ID (e.g., T1110)
        
    Returns:
        URL to MITRE ATT&CK page
    """
    return f"https://attack.mitre.org/techniques/{technique_id}/"
