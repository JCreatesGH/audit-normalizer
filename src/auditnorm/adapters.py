"""Per-source adapters into AuditEvent."""
from __future__ import annotations
from typing import Any, Callable, Dict, List
from .schema import AuditEvent, parse_ts, normalize_action, normalize_outcome


def from_servicenow(r: Dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        timestamp=parse_ts(r.get("sys_created_on") or r.get("sys_updated_on")),
        source_system="servicenow",
        actor=r.get("sys_created_by") or r.get("user", "unknown"),
        action=normalize_action(r.get("operation", "")),
        resource=f"{r.get('tablename', r.get('table',''))}:{r.get('documentkey', r.get('sys_id',''))}".strip(":"),
        outcome="success",
        raw_action=str(r.get("operation", "")),
    )


def from_cloudtrail(r: Dict[str, Any]) -> AuditEvent:
    ident = r.get("userIdentity", {})
    return AuditEvent(
        timestamp=parse_ts(r.get("eventTime")),
        source_system="aws",
        actor=ident.get("arn") or ident.get("userName", "unknown"),
        action=normalize_action(r.get("eventName", "")),
        resource=r.get("eventSource", "").replace(".amazonaws.com", "") + ":" + r.get("eventName", ""),
        outcome="failure" if r.get("errorCode") else "success",
        source_ip=r.get("sourceIPAddress"),
        raw_action=str(r.get("eventName", "")),
    )


def from_okta(r: Dict[str, Any]) -> AuditEvent:
    actor = (r.get("actor") or {}).get("alternateId") or (r.get("actor") or {}).get("displayName", "unknown")
    client_ip = ((r.get("client") or {}).get("ipAddress"))
    return AuditEvent(
        timestamp=parse_ts(r.get("published")),
        source_system="okta",
        actor=actor,
        action=normalize_action(r.get("eventType", "")),
        resource=r.get("displayMessage", r.get("eventType", "")),
        outcome=normalize_outcome((r.get("outcome") or {}).get("result", "")),
        source_ip=client_ip,
        raw_action=str(r.get("eventType", "")),
    )


def from_splunk(r: Dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        timestamp=parse_ts(r.get("_time") or r.get("time")),
        source_system="splunk",
        actor=r.get("user", "unknown"),
        action=normalize_action(r.get("action", "")),
        resource=r.get("object", r.get("dest", "")),
        outcome=normalize_outcome(r.get("status") or r.get("result") or ""),
        source_ip=r.get("src_ip") or r.get("src"),
        raw_action=str(r.get("action", "")),
    )


ADAPTERS: Dict[str, Callable[[Dict[str, Any]], AuditEvent]] = {
    "servicenow": from_servicenow, "aws": from_cloudtrail,
    "okta": from_okta, "splunk": from_splunk,
}


def normalize(records: List[Dict[str, Any]], source: str) -> List[AuditEvent]:
    if source not in ADAPTERS:
        raise ValueError(f"unknown source '{source}'; choose {list(ADAPTERS)}")
    adapter = ADAPTERS[source]
    return sorted((adapter(r) for r in records), key=lambda e: e.timestamp)


def normalize_all(sources: Dict[str, List[Dict[str, Any]]]) -> List[AuditEvent]:
    """Normalize records from several sources at once and merge them into a single
    timeline. `sources` maps source name -> its raw records, e.g.
    {"aws": [...], "okta": [...]}."""
    events: List[AuditEvent] = []
    for source, records in sources.items():
        events.extend(normalize(records, source))
    return sorted(events, key=lambda e: e.timestamp)
