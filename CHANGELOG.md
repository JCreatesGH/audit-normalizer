# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.3.0]

### Added
- **Three new source adapters** (7 → 10): `from_kubernetes` (audit.k8s.io — `verb`/`objectRef`,
  `responseStatus.code` ≥ 400 → `failure`), `from_m365` (Microsoft 365 Unified Audit Log —
  `Operation`/`ResultStatus`/`ClientIP`), and `from_cloudflare` (`actor`/`action`/`resource`
  objects, `action.result` false → `failure`).
- `detect_source` (and `normalize_auto`, the CLI `--source`/`--auto`) now recognize all three,
  so mixed batches that include Kubernetes, M365, or Cloudflare records normalize automatically.

## [0.2.0]

### Added
- Three new source adapters: **GCP Cloud Audit** (`from_gcp`), **Azure Activity
  Log** (`from_azure`), and **GitHub audit log** (`from_github`, handling
  millisecond-epoch timestamps). Dotted/slashed verbs are reduced to their last
  segment before normalization.
- **Source auto-detection** — `detect_source(record)` identifies a record's
  format from its signature fields, and `normalize_auto(records)` normalizes a
  mixed list into one merged timeline (raising on an unidentifiable record).
- CLI `--auto` mode for a flat list of mixed-source records.
- `destroy → delete` added to the verb map.

## [0.1.0]

### Added
- Common audit schema and adapters for ServiceNow, AWS CloudTrail, Okta, and
  Splunk; action/outcome normalization; `normalize` / `normalize_all`; and an
  `auditnorm` CLI (`--source`, `--all`, `--ndjson`).
