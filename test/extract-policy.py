#!/usr/bin/env python3
"""Extract the measured Rego from an initdata.toml.

Usage: extract-policy.py <initdata.toml> <out.rego>

The policy that runs in the enclave is the [data]."policy.rego" value of the
measured file. Anything else -- a loose .rego in the repo, a copy pasted into
a review -- is not what the agent enforces. Always extract from the file whose
digest is bound into the attestation report.
"""
import hashlib
import sys
import tomllib
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    raw = src.read_bytes()
    doc = tomllib.loads(raw.decode("utf-8"))
    try:
        rego = doc["data"]["policy.rego"]
    except KeyError:
        print(f"{src}: no [data].\"policy.rego\" key", file=sys.stderr)
        return 1
    dst.write_text(rego)
    print(f"{src}")
    print(f"  sha256(initdata.toml) = {hashlib.sha256(raw).hexdigest()}")
    print(f"  sha384(initdata.toml) = {hashlib.sha384(raw).hexdigest()}")
    print(f"  bytes = {len(raw)}   rego lines = {rego.count(chr(10)) + 1}")
    print(f"  extracted -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
