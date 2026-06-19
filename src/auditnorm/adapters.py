"""Per-source adapters into AuditEvent."""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional
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


def from_gcp(r: Dict[str, Any]) -> AuditEvent:
    """GCP Cloud Audit Logs (LogEntry with a protoPayload)."""
    payload = r.get("protoPayload") or {}
    method = payload.get("methodName", "")
    status = payload.get("status") or {}
    meta = payload.get("requestMetadata") or {}
    return AuditEvent(
        timestamp=parse_ts(r.get("timestamp") or payload.get("requestTime")),
        source_system="gcp",
        actor=(payload.get("authenticationInfo") or {}).get("principalEmail", "unknown"),
        action=normalize_action(method.split(".")[-1] if method else ""),
        resource=payload.get("resourceName") or payload.get("serviceName", ""),
        outcome="failure" if status.get("code") else "success",   # status.code != 0 => error
        source_ip=meta.get("callerIp"),
        raw_action=str(method),
    )


def from_azure(r: Dict[str, Any]) -> AuditEvent:
    """Azure Activity Log records (operationName / status may be {value,...})."""
    def _val(v: Any) -> str:
        return v.get("value", "") if isinstance(v, dict) else (v or "")
    op = _val(r.get("operationName"))
    status = _val(r.get("status")) or r.get("resultType", "")
    return AuditEvent(
        timestamp=parse_ts(r.get("eventTimestamp") or r.get("time")),
        source_system="azure",
        actor=r.get("caller", "unknown"),
        action=normalize_action(op.split("/")[-1] if op else ""),
        resource=r.get("resourceId") or r.get("resourceProviderName", ""),
        outcome=normalize_outcome(status),
        source_ip=r.get("callerIpAddress"),
        raw_action=str(op),
    )


def from_github(r: Dict[str, Any]) -> AuditEvent:
    """GitHub audit-log entries (action like 'repo.destroy'; ms-epoch timestamps)."""
    action = r.get("action", "")
    ts = r.get("@timestamp", r.get("created_at"))
    if isinstance(ts, (int, float)) and ts > 1e12:    # GitHub uses millisecond epochs
        ts = ts / 1000.0
    loc = r.get("actor_location") if isinstance(r.get("actor_location"), dict) else {}
    return AuditEvent(
        timestamp=parse_ts(ts),
        source_system="github",
        actor=r.get("actor", "unknown"),
        action=normalize_action(action.split(".")[-1] if action else ""),
        resource=r.get("repo") or r.get("org", ""),
        outcome="success",                            # the audit log records completed actions
        source_ip=r.get("actor_ip") or loc.get("ip"),
        raw_action=str(action),
    )


def from_kubernetes(r: Dict[str, Any]) -> AuditEvent:
    """Kubernetes audit events (audit.k8s.io/v1)."""
    user = r.get("user") or {}
    ref = r.get("objectRef") or {}
    resp = r.get("responseStatus") or {}
    ips = r.get("sourceIPs") or []
    resource = "/".join(p for p in (ref.get("namespace"), ref.get("resource"), ref.get("name")) if p)
    code = resp.get("code")
    if isinstance(code, int):
        outcome = "failure" if code >= 400 else "success"
    else:
        outcome = "unknown"
    return AuditEvent(
        timestamp=parse_ts(r.get("requestReceivedTimestamp") or r.get("stageTimestamp")),
        source_system="kubernetes",
        actor=user.get("username", "unknown"),
        action=normalize_action(r.get("verb", "")),
        resource=resource or ref.get("resource", ""),
        outcome=outcome,
        source_ip=ips[0] if ips else None,
        raw_action=str(r.get("verb", "")),
    )


def from_m365(r: Dict[str, Any]) -> AuditEvent:
    """Microsoft 365 / Office 365 Unified Audit Log records."""
    return AuditEvent(
        timestamp=parse_ts(r.get("CreationTime")),
        source_system="m365",
        actor=r.get("UserId", "unknown"),
        action=normalize_action(r.get("Operation", "")),
        resource=r.get("ObjectId") or r.get("Workload", ""),
        outcome=normalize_outcome(r.get("ResultStatus", "")),
        source_ip=r.get("ClientIP") or r.get("ActorIpAddress"),
        raw_action=str(r.get("Operation", "")),
    )


def from_cloudflare(r: Dict[str, Any]) -> AuditEvent:
    """Cloudflare audit logs (actor/action/resource objects, `when` timestamp)."""
    actor = r.get("actor") or {}
    action = r.get("action") or {}
    resource = r.get("resource") or {}
    res = ":".join(p for p in (resource.get("type"), resource.get("id")) if p)
    result = action.get("result", True)        # boolean; absent => assume success
    return AuditEvent(
        timestamp=parse_ts(r.get("when")),
        source_system="cloudflare",
        actor=actor.get("email") or actor.get("id", "unknown"),
        action=normalize_action(action.get("type", "")),
        resource=res or resource.get("type", ""),
        outcome="success" if result else "failure",
        source_ip=actor.get("ip"),
        raw_action=str(action.get("type", "")),
    )


ADAPTERS: Dict[str, Callable[[Dict[str, Any]], AuditEvent]] = {
    "servicenow": from_servicenow, "aws": from_cloudtrail,
    "okta": from_okta, "splunk": from_splunk,
    "gcp": from_gcp, "azure": from_azure, "github": from_github,
    "kubernetes": from_kubernetes, "m365": from_m365, "cloudflare": from_cloudflare,
}


def detect_source(record: Dict[str, Any]) -> Optional[str]:
    """Best-effort guess of which source a raw record came from, by signature
    fields. Returns the source name or None if it can't tell."""
    r = record
    if "protoPayload" in r:
        return "gcp"
    if "operationName" in r and ("eventTimestamp" in r or "callerIpAddress" in r or "resultType" in r):
        return "azure"
    if "eventName" in r and "eventSource" in r:
        return "aws"
    if "eventType" in r and "published" in r:
        return "okta"
    if "CreationTime" in r and "Operation" in r:
        return "m365"
    if "requestReceivedTimestamp" in r or ("objectRef" in r and "verb" in r):
        return "kubernetes"
    if "when" in r and isinstance(r.get("action"), dict):
        return "cloudflare"
    if "sys_created_on" in r or "sys_updated_on" in r:
        return "servicenow"
    if "action" in r and "actor" in r and ("@timestamp" in r or "created_at" in r):
        return "github"
    if "_time" in r or ("action" in r and any(k in r for k in ("user", "status", "object", "dest"))):
        return "splunk"
    return None


def normalize_auto(records: List[Dict[str, Any]]) -> List[AuditEvent]:
    """Normalize a list of mixed-source records, detecting each one's format.
    Raises ValueError on a record whose source can't be identified."""
    events: List[AuditEvent] = []
    for i, r in enumerate(records):
        src = detect_source(r)
        if src is None:
            raise ValueError(f"could not detect the audit source of record {i}")
        events.append(ADAPTERS[src](r))
    return sorted(events, key=lambda e: e.timestamp)


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
