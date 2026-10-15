"""Normalize heterogeneous inputs (generic JSON, CSV rows, Wazuh alerts) into one schema."""
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_STR = 1024


class NormalizationError(ValueError):
    pass


def clean_str(value: Any, max_len: int = MAX_STR) -> str | None:
    """Strip control characters and cap length. HTML escaping is the UI's job (React escapes by default)."""
    if value is None:
        return None
    s = _CTRL.sub("", str(value)).strip()
    return s[:max_len] or None


def clean_ip(value: Any) -> str | None:
    s = clean_str(value, 64)
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        raise NormalizationError(f"invalid IP address: {s!r}")


def parse_timestamp(value: Any) -> datetime:
    if value in (None, ""):
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if re.fullmatch(r"\d{10}(\.\d+)?", s):
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        s = s.replace("Z", "+00:00")
        s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # Wazuh style +0000
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            raise NormalizationError(f"invalid timestamp: {value!r}")
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def wazuh_level_to_severity(level: int) -> str:
    if level <= 4:
        return "low"
    if level <= 7:
        return "medium"
    if level <= 11:
        return "high"
    return "critical"


def normalize_severity(value: Any) -> str:
    if isinstance(value, bool):
        raise NormalizationError("invalid severity")
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        return wazuh_level_to_severity(int(value))
    s = str(value or "low").strip().lower()
    aliases = {"info": "low", "informational": "low", "warning": "medium", "warn": "medium",
               "med": "medium", "error": "high", "crit": "critical", "severe": "critical"}
    s = aliases.get(s, s)
    if s not in SEVERITIES:
        raise NormalizationError(f"invalid severity: {value!r}")
    return s


def _safe_raw(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}

    def walk(v, depth=0):
        if depth > 6:
            return None
        if isinstance(v, dict):
            return {clean_str(k, 128) or "_": walk(x, depth + 1) for k, x in list(v.items())[:100]}
        if isinstance(v, list):
            return [walk(x, depth + 1) for x in v[:100]]
        return clean_str(v, 2048) if isinstance(v, str) else v
    return walk(raw)


def normalize_event(data: dict) -> dict:
    """Return a dict in the common schema (without dedupe_hash / ingested_at)."""
    event_type = clean_str(data.get("event_type"), 128)
    if not event_type:
        raise NormalizationError("event_type is required")
    return {
        "timestamp": parse_timestamp(data.get("timestamp")),
        "src_ip": clean_ip(data.get("src_ip")),
        "dst_ip": clean_ip(data.get("dst_ip")),
        "username": clean_str(data.get("username"), 128),
        "event_type": event_type.lower().replace(" ", "_"),
        "severity": normalize_severity(data.get("severity", "low")),
        "host": clean_str(data.get("host"), 128),
        "source": clean_str(data.get("source"), 64) or "api",
        "raw": _safe_raw(data.get("raw")),
        "is_synthetic": bool(data.get("is_synthetic", False)),
    }


_WAZUH_TYPE_MAP = (  # (rule group fragment, event_type)
    ("authentication_failed", "failed_login"), ("authentication_failures", "failed_login"),
    ("authentication_success", "successful_login"), ("sudo", "privilege_escalation"),
    ("privilege_escalation", "privilege_escalation"), ("syscheck", "file_access"),
    ("web", "web_access"), ("firewall", "network_connection"), ("recon", "port_scan"),
)


def normalize_wazuh_alert(alert: dict) -> dict:
    """Map a Wazuh alert JSON (alerts.json format) to the common schema."""
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    groups = [str(g).lower() for g in (rule.get("groups") or [])]
    event_type = next((t for frag, t in _WAZUH_TYPE_MAP if any(frag in g for g in groups)), None)
    event_type = event_type or clean_str(rule.get("description"), 64) or "wazuh_alert"
    try:
        severity = wazuh_level_to_severity(int(rule.get("level", 0)))
    except (TypeError, ValueError):
        severity = "low"
    return normalize_event({
        "timestamp": alert.get("timestamp"),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "dst_ip": data.get("dstip") or data.get("dst_ip"),
        "username": data.get("dstuser") or data.get("srcuser") or data.get("user"),
        "event_type": event_type,
        "severity": severity,
        "host": agent.get("name"),
        "source": "wazuh",
        "raw": alert,
    })
