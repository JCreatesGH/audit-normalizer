"""Command-line interface: normalize audit records into the common schema as JSON."""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

from .adapters import normalize, normalize_all, normalize_auto, ADAPTERS


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditnorm", description="Normalize audit logs into one common schema.")
    parser.add_argument("file", nargs="?", help="JSON input (default: stdin)")
    parser.add_argument("--source", choices=sorted(ADAPTERS),
                        help="source of a flat list of records")
    parser.add_argument("--all", action="store_true",
                        help="input is an object mapping source -> [records]; merge all")
    parser.add_argument("--auto", action="store_true",
                        help="input is a flat list of mixed records; auto-detect each one's source")
    parser.add_argument("--ndjson", action="store_true", help="emit one JSON object per line")
    args = parser.parse_args(argv)

    if not args.all and not args.source and not args.auto:
        print("error: provide --source <name>, --all, or --auto", file=sys.stderr)
        return 2

    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return 2

    try:
        if args.all:
            events = normalize_all(data)
        elif args.auto:
            events = normalize_auto(data)
        else:
            events = normalize(data, args.source)
    except (ValueError, AttributeError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    rows = [e.to_dict() for e in events]
    if args.ndjson:
        for row in rows:
            print(json.dumps(row))
    else:
        print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
