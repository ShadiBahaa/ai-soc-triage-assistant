"""
Tests for the normalization module.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsing.normalize import normalize, severity_from_event, is_external_ip


class TestNormalize:
    """Test cases for normalize function."""
    
    def test_normalize_auth_event(self):
        """Test normalizing an auth event."""
        raw = {
            "source": "auth",
            "timestamp": "2024-01-15T10:00:00Z",
            "host": "srv-web-01",
            "user": "alice",
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.2.20",
            "message": "Successful login",
            "event_type": "auth_success",
            "status": "success"
        }
        
        result = normalize(raw)
        
        assert result["source"] == "auth"
        assert result["host"] == "srv-web-01"
        assert result["user"] == "alice"
        assert result["event_type"] == "auth_success"
        assert result["action"] == "Successful login"
        assert result["raw"] == raw
    
    def test_normalize_web_event(self):
        """Test normalizing a web event."""
        raw = {
            "source": "web",
            "timestamp": "2024-01-15T10:00:00Z",
            "host": "srv-web-01",
            "src_ip": "198.51.100.10",
            "path": "/.env",
            "http_method": "GET",
            "status_code": 200,
            "event_type": "web_access"
        }
        
        result = normalize(raw)
        
        assert result["source"] == "web"
        assert result["action"] == "/.env"
        assert result["severity_hint"] == "high"
    
    def test_normalize_endpoint_event(self):
        """Test normalizing an endpoint event."""
        raw = {
            "source": "endpoint",
            "timestamp": "2024-01-15T10:00:00Z",
            "host": "wkst-01",
            "user": "bob",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "event_type": "process_start"
        }
        
        result = normalize(raw)
        
        assert result["source"] == "endpoint"
        assert result["action"] == "mimikatz.exe sekurlsa::logonpasswords"
        assert result["severity_hint"] == "critical"
    
    def test_normalize_missing_fields(self):
        """Test normalizing event with missing fields."""
        raw = {
            "timestamp": "2024-01-15T10:00:00Z"
        }
        
        result = normalize(raw)
        
        assert result["source"] == "other"
        assert result["event_type"] == "unknown"
        assert result["host"] is None


class TestSeverityFromEvent:
    """Test cases for severity detection."""
    
    def test_auth_failure_medium(self):
        """Auth failures should be medium severity."""
        evt = {"event_type": "auth_failure"}
        assert severity_from_event(evt) == "medium"
    
    def test_external_auth_success_high(self):
        """Auth success from external IP should be high."""
        evt = {
            "event_type": "auth_success",
            "src_ip": "198.51.100.10"
        }
        assert severity_from_event(evt) == "high"
    
    def test_internal_auth_success_none(self):
        """Auth success from internal IP should be None."""
        evt = {
            "event_type": "auth_success",
            "src_ip": "10.0.1.10"
        }
        assert severity_from_event(evt) is None
    
    def test_suspicious_process_critical(self):
        """Suspicious process execution should be critical."""
        evt = {
            "process_name": "mimikatz.exe"
        }
        assert severity_from_event(evt) == "critical"


class TestIsExternalIP:
    """Test cases for IP classification."""
    
    def test_external_ip(self):
        """Test external IP detection."""
        assert is_external_ip("198.51.100.10") is True
        assert is_external_ip("203.0.113.55") is True
        assert is_external_ip("192.0.2.77") is True
    
    def test_internal_ip(self):
        """Test internal IP detection."""
        assert is_external_ip("10.0.1.10") is False
        assert is_external_ip("172.16.0.1") is False
    
    def test_none_ip(self):
        """Test None IP handling."""
        assert is_external_ip(None) is False
        assert is_external_ip("") is False
