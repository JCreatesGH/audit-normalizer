from auditnorm import (from_servicenow, from_cloudtrail, from_okta, from_splunk, normalize)


def test_servicenow_mapping():
    ev = from_servicenow({"sys_created_on": "2026-06-01 10:00:00", "sys_created_by": "admin",
                          "operation": "insert", "tablename": "incident", "documentkey": "abc"})
    assert ev.source_system == "servicenow"
    assert ev.actor == "admin"
    assert ev.action == "create"          # insert -> create
    assert ev.resource == "incident:abc"


def test_cloudtrail_mapping_and_failure():
    ev = from_cloudtrail({"eventTime": "2026-06-01T10:00:00Z",
                          "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
                          "eventName": "DeleteBucket", "eventSource": "s3.amazonaws.com",
                          "sourceIPAddress": "1.2.3.4", "errorCode": "AccessDenied"})
    assert ev.source_system == "aws"
    assert ev.actor.endswith("user/bob")
    assert ev.outcome == "failure"
    assert ev.source_ip == "1.2.3.4"
    assert ev.resource.startswith("s3:")


def test_okta_mapping():
    ev = from_okta({"published": "2026-06-01T10:00:00Z",
                    "actor": {"alternateId": "bob@acme.com"},
                    "eventType": "user.session.start",
                    "outcome": {"result": "SUCCESS"},
                    "client": {"ipAddress": "9.9.9.9"}})
    assert ev.action == "login"           # user.session.start -> login
    assert ev.actor == "bob@acme.com"
    assert ev.outcome == "success" and ev.source_ip == "9.9.9.9"


def test_splunk_mapping():
    ev = from_splunk({"_time": "2026-06-01T10:00:00Z", "user": "carol",
                      "action": "modify", "object": "policy-7", "status": "success", "src_ip": "8.8.8.8"})
    assert ev.action == "update" and ev.resource == "policy-7"


def test_normalize_sorts_and_validates():
    recs = [{"sys_created_on": "2026-06-01 10:05:00", "operation": "delete", "sys_created_by": "a"},
            {"sys_created_on": "2026-06-01 10:00:00", "operation": "insert", "sys_created_by": "b"}]
    events = normalize(recs, "servicenow")
    assert [e.action for e in events] == ["create", "delete"]   # sorted by time
    import pytest
    with pytest.raises(ValueError):
        normalize(recs, "nope")


def test_to_dict_is_serializable():
    ev = from_splunk({"_time": "2026-06-01T10:00:00Z", "user": "x", "action": "login"})
    d = ev.to_dict()
    assert isinstance(d["timestamp"], str) and d["source_system"] == "splunk"
