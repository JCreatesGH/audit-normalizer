# audit-normalizer

[![CI](https://github.com/JCreatesGH/audit-normalizer/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/audit-normalizer/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit data lives in a dozen incompatible shapes. `auditnorm` maps logs from **ServiceNow**, **AWS CloudTrail**, **Okta**, and **Splunk** into one common, OCSF/ECS-flavored schema so you can search, correlate, and report on activity across every system.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install auditnorm
```

## Use it

```python
from auditnorm import normalize, normalize_all

events = normalize(cloudtrail_records, source="aws")
for e in events:
    print(e.timestamp, e.source_system, e.actor, e.action, e.resource, e.outcome)
    e.to_dict()    # JSON-serializable common record

# merge several systems into one sorted timeline
timeline = normalize_all({"aws": cloudtrail_records, "okta": okta_records})
```

## CLI

Installing the package adds an `auditnorm` command — pipe raw logs in, get the common schema out:

```bash
$ auditnorm okta-events.json --source okta            # JSON array of common records
$ cat cloudtrail.json | auditnorm --source aws --ndjson
$ auditnorm bundle.json --all                         # bundle = {"aws":[...], "okta":[...]}
```

## The common schema

`timestamp · source_system · actor · action · resource · outcome · source_ip · raw_action`

- **Normalized verbs** — vendor actions map to a small set: `insert/post → create`, `modify/put → update`, `remove → delete`, `user.session.start → login`, etc. (`raw_action` keeps the original).
- **Outcome** — every source's status/result is mapped to `success` / `failure` / `unknown` (CloudTrail `errorCode`, Okta `outcome.result`, Splunk `status`/`result`, …) via `normalize_outcome`, so the field is genuinely uniform.
- **Adapters are plain functions** (`from_servicenow`, `from_cloudtrail`, `from_okta`, `from_splunk`), so adding a new source is a few lines.

## Development

```bash
pip install -e .[dev] && python -m pytest -q   # 10 tests
```

## License

MIT
