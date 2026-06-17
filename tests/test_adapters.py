from auditnorm import (from_servicenow, from_cloudtrail, from_okta, from_splunk,
                       normalize, normalize_all, normalize_outcome)
from auditnorm.cli import main


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


def test_outcome_is_normalized_to_three_values():
    assert normalize_outcome("FAILED") == "failure"
    assert normalize_outcome("200") == "success"
    assert normalize_outcome("blocked") == "failure"
    assert normalize_outcome("weird-status") == "unknown"
    assert normalize_outcome("") == "unknown"
    # the splunk adapter now goes through it (previously passed raw strings through)
    ev = from_splunk({"_time": "2026-06-01T10:00:00Z", "user": "c", "action": "login", "status": "failed"})
    assert ev.outcome == "failure"


def test_normalize_all_merges_sources_into_one_timeline():
    sources = {
        "servicenow": [{"sys_created_on": "2026-06-01 10:05:00", "operation": "delete", "sys_created_by": "a"}],
        "okta": [{"published": "2026-06-01T10:00:00Z", "actor": {"alternateId": "b@x"},
                  "eventType": "user.session.start", "outcome": {"result": "SUCCESS"}}],
    }
    events = normalize_all(sources)
    assert [e.source_system for e in events] == ["okta", "servicenow"]   # sorted by time across sources


def test_cli_source_and_all(tmp_path, capsys):
    import json
    flat = tmp_path / "okta.json"
    flat.write_text(json.dumps([{"published": "2026-06-01T10:00:00Z",
                                 "actor": {"alternateId": "b@x"}, "eventType": "user.session.start",
                                 "outcome": {"result": "SUCCESS"}}]))
    assert main([str(flat), "--source", "okta"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["action"] == "login" and rows[0]["outcome"] == "success"

    bundle = tmp_path / "all.json"
    bundle.write_text(json.dumps({"splunk": [{"_time": "2026-06-01T09:00:00Z", "user": "c",
                                              "action": "modify", "status": "failed"}]}))
    assert main([str(bundle), "--all"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["action"] == "update" and rows[0]["outcome"] == "failure"


def test_cli_requires_source_or_all(tmp_path, capsys):
    f = tmp_path / "x.json"
    f.write_text("[]")
    assert main([str(f)]) == 2
    assert "--source" in capsys.readouterr().err
