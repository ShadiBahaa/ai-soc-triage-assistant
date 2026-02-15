"""
Tests for the correlation module.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.correlation.correlate import detect_signals, correlate_events, parse_ts


class TestDetectSignals:
    """Test cases for signal detection."""
    
    def test_detect_bruteforce(self):
        """Test brute force detection."""
        events = [
            {"event_type": "auth_failure"} for _ in range(15)
        ]
        
        signals = detect_signals(events)
        
        signal_names = [s["signal"] for s in signals]
        assert "possible_bruteforce" in signal_names
    
    def test_detect_bruteforce_then_success(self):
        """Test brute force followed by success detection."""
        events = [{"event_type": "auth_failure"} for _ in range(15)]
        events.append({"event_type": "auth_success"})
        
        signals = detect_signals(events)
        
        signal_names = [s["signal"] for s in signals]
        assert "possible_bruteforce" in signal_names
        assert "bruteforce_then_success" in signal_names
    
    def test_detect_suspicious_web(self):
        """Test suspicious web path detection."""
        events = [
            {"event_type": "web_access", "raw": {"path": "/.env"}},
            {"event_type": "web_access", "raw": {"path": "/backup.zip"}}
        ]
        
        signals = detect_signals(events)
        
        signal_names = [s["signal"] for s in signals]
        assert "suspicious_web_paths" in signal_names
    
    def test_detect_port_scan(self):
        """Test port scan detection."""
        events = [
            {"event_type": "fw_deny", "raw": {"dst_port": 22 + i}} 
            for i in range(10)
        ]
        
        signals = detect_signals(events)
        
        signal_names = [s["signal"] for s in signals]
        assert "possible_port_scan" in signal_names
    
    def test_detect_suspicious_process(self):
        """Test suspicious process detection."""
        events = [
            {"event_type": "process_start", "raw": {"process_name": "mimikatz.exe"}}
        ]
        
        signals = detect_signals(events)
        
        signal_names = [s["signal"] for s in signals]
        assert "suspicious_process_execution" in signal_names
    
    def test_no_signals_benign(self):
        """Test no signals for benign activity."""
        events = [
            {"event_type": "auth_success"} for _ in range(3)
        ]
        
        signals = detect_signals(events)
        
        assert len(signals) == 0


class TestCorrelateEvents:
    """Test cases for event correlation."""
    
    def test_correlate_basic(self):
        """Test basic correlation."""
        events = [
            {
                "timestamp": f"2024-01-15T10:{i:02d}:00Z",
                "host": "srv-01",
                "user": "alice",
                "src_ip": "198.51.100.10",
                "event_type": "auth_failure"
            }
            for i in range(15)
        ]
        
        incidents = correlate_events(events, min_events=5)
        
        assert len(incidents) == 1
        assert incidents[0]["incident_type"] == "Brute Force Attack"
    
    def test_correlate_groups_by_key(self):
        """Test that correlation groups by key."""
        events = []
        # Group 1: alice
        for i in range(15):
            events.append({
                "timestamp": f"2024-01-15T10:0{i % 10}:00Z",
                "host": "srv-01",
                "user": "alice",
                "src_ip": "198.51.100.10",
                "event_type": "auth_failure"
            })
        # Group 2: bob
        for i in range(15):
            events.append({
                "timestamp": f"2024-01-15T11:0{i % 10}:00Z",
                "host": "srv-02",
                "user": "bob",
                "src_ip": "203.0.113.55",
                "event_type": "auth_failure"
            })
        
        incidents = correlate_events(events, min_events=5)
        
        assert len(incidents) == 2
    
    def test_correlate_min_events(self):
        """Test minimum events threshold."""
        events = [
            {
                "timestamp": f"2024-01-15T10:0{i}:00Z",
                "host": "srv-01",
                "user": "alice",
                "src_ip": "198.51.100.10",
                "event_type": "auth_failure"
            }
            for i in range(3)
        ]
        
        incidents = correlate_events(events, min_events=5)
        
        assert len(incidents) == 0


class TestParseTimestamp:
    """Test cases for timestamp parsing."""
    
    def test_parse_z_suffix(self):
        """Test parsing timestamp with Z suffix."""
        ts = "2024-01-15T10:30:00Z"
        result = parse_ts(ts)
        
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30
    
    def test_parse_timezone(self):
        """Test parsing timestamp with timezone."""
        ts = "2024-01-15T10:30:00+00:00"
        result = parse_ts(ts)
        
        assert result.year == 2024
