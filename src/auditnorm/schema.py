"""The common audit event schema (loosely OCSF / ECS-flavored)."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class AuditEvent:
    timestamp: datetime
    source_system: str        # servicenow | aws | okta | splunk
    actor: str                # who did it
    action: str               # normalized verb (create/update/delete/login/...)
    resource: str             # what was acted on
    outcome: str              # success | failure | unknown
    source_ip: Optional[str] = None
    raw_action: str = ""      # original action string

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


def parse_ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# map many vendor verbs to a small normalized set
_ACTION_MAP = {
    "insert": "create", "create": "create", "post": "create",
    "update": "update", "patch": "update", "put": "update", "modify": "update",
    "delete": "delete", "remove": "delete",
    "read": "read", "get": "read", "view": "read", "list": "read",
    "login": "login", "logout": "logout", "authenticate": "login",
    "user.session.start": "login", "user.session.end": "logout",
}


def normalize_action(raw: str) -> str:
    return _ACTION_MAP.get(str(raw).strip().lower(), str(raw).strip().lower() or "unknown")
