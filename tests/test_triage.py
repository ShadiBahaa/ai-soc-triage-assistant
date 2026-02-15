"""
Tests for the triage module.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.triage.score import score_incident, generate_recommendations
from src.triage.summarize import summarize_incident, generate_narrative
from src.triage.mitre_mapping import MITRE_MAP, get_mitre_info, get_mitre_url


class TestScoreIncident:
    """Test cases for incident scoring."""
    
    def test_score_bruteforce_medium(self):
        """Test scoring of brute force signal."""
        signals = [{"signal": "possible_bruteforce", "count": 15}]
        
        result = score_incident(signals)
        
        assert result["severity"] in ["medium", "low"]
        assert result["confidence"] > 0.5
        assert len(result["mitre"]) == 1
    
    def test_score_bruteforce_success_high(self):
        """Test scoring of brute force with success."""
        signals = [
            {"signal": "possible_bruteforce", "count": 15},
            {"signal": "bruteforce_then_success", "count": 1}
        ]
        
        result = score_incident(signals)
        
        assert result["severity"] in ["high", "critical"]
        assert result["requires_immediate_attention"] is True
    
    def test_score_multiple_signals(self):
        """Test scoring with multiple signals."""
        signals = [
            {"signal": "bruteforce_then_success", "count": 1},
            {"signal": "suspicious_web_paths", "count": 5},
            {"signal": "suspicious_process_execution", "count": 2}
        ]
        
        result = score_incident(signals)
        
        assert result["severity"] == "critical"
        assert result["confidence"] >= 0.9
        assert len(result["mitre"]) == 3
    
    def test_score_empty_signals(self):
        """Test scoring with no signals."""
        signals = []
        
        result = score_incident(signals)
        
        assert result["severity"] == "low"
        assert result["confidence"] == 0.5
    
    def test_recommendations_generated(self):
        """Test that recommendations are generated."""
        signals = [{"signal": "possible_bruteforce", "count": 15}]
        
        result = score_incident(signals)
        
        assert len(result["recommended_actions"]) > 0


class TestGenerateRecommendations:
    """Test cases for recommendation generation."""
    
    def test_bruteforce_recommendations(self):
        """Test recommendations for brute force."""
        mitre = [{"technique": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access", "description": "Test", "url": "#"}]
        signals = [{"signal": "possible_bruteforce"}]
        
        actions = generate_recommendations(mitre, signals)
        
        assert any("MFA" in a for a in actions)
        assert any("source IP" in a.lower() or "ip" in a.lower() for a in actions)
    
    def test_web_exploit_recommendations(self):
        """Test recommendations for web exploitation."""
        mitre = [{"technique": "T1190", "technique_name": "Exploit", "tactic": "Initial Access", "description": "Test", "url": "#"}]
        signals = [{"signal": "suspicious_web_paths"}]
        
        actions = generate_recommendations(mitre, signals)
        
        assert any("web" in a.lower() for a in actions)


class TestSummarizeIncident:
    """Test cases for incident summarization."""
    
    def test_summary_contains_key_info(self):
        """Test that summary contains key information."""
        incident = {
            "incident_id": "INC-1234567",
            "incident_type": "Brute Force Attack",
            "key": {"host": "srv-01", "user": "alice", "src_ip": "198.51.100.10"},
            "time_range": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00", "duration_minutes": 30},
            "signals": [{"signal": "possible_bruteforce", "count": 15, "description": "Test"}],
            "event_count": 15
        }
        triage = {
            "severity": "high",
            "severity_score": 6.0,
            "confidence": 0.82,
            "mitre": [{"technique": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access", "description": "Brute force attack", "url": "https://attack.mitre.org/techniques/T1110/"}],
            "recommended_actions": ["Action 1"],
            "requires_immediate_attention": True
        }
        
        summary = summarize_incident(incident, triage)
        
        assert "INC-1234567" in summary
        assert "alice" in summary
        assert "srv-01" in summary
        assert "HIGH" in summary
    
    def test_summary_markdown_format(self):
        """Test that summary is in markdown format."""
        incident = {
            "incident_id": "INC-1234567",
            "incident_type": "Test",
            "key": {"host": "srv-01", "user": "alice", "src_ip": "10.0.0.1"},
            "time_range": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00", "duration_minutes": 30},
            "signals": [],
            "event_count": 5
        }
        triage = {
            "severity": "low",
            "confidence": 0.5,
            "mitre": [],
            "recommended_actions": [],
            "requires_immediate_attention": False
        }
        
        summary = summarize_incident(incident, triage)
        
        assert "##" in summary  # Has headers


class TestMitreMapping:
    """Test cases for MITRE mapping."""
    
    def test_known_signal_mapping(self):
        """Test mapping of known signal."""
        info = get_mitre_info("possible_bruteforce")
        
        assert info["technique"] == "T1110"
        assert info["tactic"] == "Credential Access"
    
    def test_unknown_signal_mapping(self):
        """Test mapping of unknown signal."""
        info = get_mitre_info("unknown_signal")
        
        assert "technique" in info
        assert info["severity_weight"] == 1
    
    def test_mitre_url_generation(self):
        """Test MITRE URL generation."""
        url = get_mitre_url("T1110")
        
        assert url == "https://attack.mitre.org/techniques/T1110/"
    
    def test_all_mappings_have_required_fields(self):
        """Test all mappings have required fields."""
        required_fields = ["technique", "technique_name", "tactic", "severity_weight"]
        
        for signal, mapping in MITRE_MAP.items():
            for field in required_fields:
                assert field in mapping, f"Missing {field} in {signal}"
