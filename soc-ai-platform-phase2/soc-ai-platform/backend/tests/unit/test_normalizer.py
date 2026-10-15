import pytest
from app.ingestion.dedupe import compute_dedupe_hash
from app.ingestion.normalizer import (NormalizationError, normalize_event, normalize_severity,
                                      normalize_wazuh_alert, wazuh_level_to_severity)


def test_normalize_basic():
    ev = normalize_event({"timestamp": "2026-01-01T10:00:00Z", "src_ip": "10.0.0.5", "event_type": "Failed Login",
                          "severity": "HIGH", "username": "bob"})
    assert ev["event_type"] == "failed_login" and ev["severity"] == "high"
    assert ev["timestamp"].tzinfo is not None


def test_invalid_ip_rejected():
    with pytest.raises(NormalizationError):
        normalize_event({"event_type": "x", "src_ip": "999.1.1.1"})


def test_missing_event_type():
    with pytest.raises(NormalizationError):
        normalize_event({"src_ip": "10.0.0.1"})


def test_control_chars_stripped():
    ev = normalize_event({"event_type": "x", "username": "bo\x00b\x07"})
    assert ev["username"] == "bob"


@pytest.mark.parametrize("level,sev", [(0, "low"), (4, "low"), (5, "medium"), (8, "high"), (12, "critical")])
def test_wazuh_levels(level, sev):
    assert wazuh_level_to_severity(level) == sev


def test_severity_invalid():
    with pytest.raises(NormalizationError):
        normalize_severity("banana")


def test_wazuh_alert_mapping():
    alert = {"timestamp": "2026-01-01T10:00:00.000+0000", "rule": {"level": 10, "groups": ["authentication_failed"]},
             "agent": {"name": "web01"}, "data": {"srcip": "203.0.113.9", "dstuser": "root"}}
    ev = normalize_wazuh_alert(alert)
    assert (ev["event_type"], ev["severity"], ev["host"], ev["source"]) == ("failed_login", "high", "web01", "wazuh")
    assert ev["src_ip"] == "203.0.113.9" and ev["username"] == "root"


def test_dedupe_hash_stable_and_sensitive():
    a = normalize_event({"timestamp": "2026-01-01T10:00:00Z", "event_type": "x", "src_ip": "10.0.0.1"})
    b = dict(a)
    assert compute_dedupe_hash(a) == compute_dedupe_hash(b)
    b["src_ip"] = "10.0.0.2"
    assert compute_dedupe_hash(a) != compute_dedupe_hash(b)
