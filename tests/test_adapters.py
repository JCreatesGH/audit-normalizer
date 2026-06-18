from auditnorm import (from_servicenow, from_cloudtrail, from_okta, from_splunk,
                       from_gcp, from_azure, from_github, detect_source, normalize_auto,
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


def test_gcp_mapping():
    ev = from_gcp({"timestamp": "2026-06-01T10:00:00Z", "protoPayload": {
        "authenticationInfo": {"principalEmail": "svc@proj.iam"},
        "methodName": "storage.buckets.delete", "resourceName": "projects/_/buckets/x",
        "status": {"code": 7, "message": "PERMISSION_DENIED"},
        "requestMetadata": {"callerIp": "1.1.1.1"}}})
    assert ev.source_system == "gcp" and ev.actor == "svc@proj.iam"
    assert ev.action == "delete" and ev.outcome == "failure" and ev.source_ip == "1.1.1.1"
    ok = from_gcp({"timestamp": "2026-06-01T10:00:00Z",
                   "protoPayload": {"methodName": "storage.buckets.get", "status": {}}})
    assert ok.outcome == "success" and ok.action == "read"   # no status.code => success


def test_azure_mapping():
    ev = from_azure({"eventTimestamp": "2026-06-01T10:00:00Z", "caller": "alice@x",
                     "operationName": {"value": "Microsoft.Compute/virtualMachines/delete"},
                     "status": {"value": "Succeeded"}, "callerIpAddress": "2.2.2.2",
                     "resourceId": "/subs/s/vmX"})
    assert ev.source_system == "azure" and ev.actor == "alice@x"
    assert ev.action == "delete" and ev.outcome == "success" and ev.source_ip == "2.2.2.2"


def test_github_mapping_ms_epoch():
    ev = from_github({"action": "repo.destroy", "actor": "bob",
                      "@timestamp": 1717236000000, "repo": "acme/app", "actor_ip": "3.3.3.3"})
    assert ev.source_system == "github" and ev.actor == "bob"
    assert ev.action == "delete"                 # destroy -> delete
    assert ev.resource == "acme/app" and ev.source_ip == "3.3.3.3"
    assert ev.timestamp.year == 2024             # 1717236000000 ms -> 2024-06-01 (not the year 56000)


def test_detect_source():
    assert detect_source({"protoPayload": {}}) == "gcp"
    assert detect_source({"operationName": {"value": "x"}, "eventTimestamp": "t"}) == "azure"
    assert detect_source({"eventName": "x", "eventSource": "y"}) == "aws"
    assert detect_source({"eventType": "x", "published": "t"}) == "okta"
    assert detect_source({"sys_created_on": "t"}) == "servicenow"
    assert detect_source({"action": "repo.create", "actor": "a", "@timestamp": 1}) == "github"
    assert detect_source({"_time": "t", "action": "login", "user": "u"}) == "splunk"
    assert detect_source({"foo": "bar"}) is None


def test_normalize_auto_mixed_and_unknown():
    import pytest
    recs = [
        {"protoPayload": {"methodName": "x.get", "status": {}}, "timestamp": "2026-06-01T10:05:00Z"},
        {"eventType": "user.session.start", "published": "2026-06-01T10:00:00Z",
         "actor": {"alternateId": "b@x"}, "outcome": {"result": "SUCCESS"}},
    ]
    evs = normalize_auto(recs)
    assert [e.source_system for e in evs] == ["okta", "gcp"]   # sorted by time across sources
    with pytest.raises(ValueError):
        normalize_auto([{"foo": "bar"}])


def test_cli_auto(tmp_path, capsys):
    import json
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps([
        {"action": "repo.create", "actor": "bob", "@timestamp": 1717236000000, "repo": "acme/app"},
        {"_time": "2026-06-01T09:00:00Z", "user": "c", "action": "login", "status": "success"},
    ]))
    assert main([str(f), "--auto"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["source_system"] for r in rows} == {"github", "splunk"}
