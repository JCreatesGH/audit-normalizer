# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

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
