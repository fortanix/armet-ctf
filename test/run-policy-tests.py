#!/usr/bin/env python3
"""Offline regression tests for the measured agent policy.

    ./test/run-policy-tests.py [initdata.toml] [--opa /path/to/opa]

What it does, in order:

  1. extracts [data]."policy.rego" from the measured initdata.toml;
  2. runs `opa check --strict` on it, which is a hard gate -- a policy that
     does not compile cannot be the policy that admitted anything;
  3. evaluates each case in test/cases.json against the extracted policy and
     compares the verdict with the expected one.

A rule with no `default` is undefined rather than false when it does not hold,
so an empty result set counts as false here.

This exercises rule logic against crafted agent requests. It does not replace
booting the policy on the node: OPA and the regorus engine inside the guest are
different implementations, and only the second one is authoritative.
"""
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = "data.agent_policy"


def evaluate(opa: str, rego: Path, rule: str, doc: dict) -> bool:
    proc = subprocess.run(
        [opa, "eval", "-d", str(rego), "--stdin-input", "--format", "json", f"{PKG}.{rule}"],
        input=json.dumps(doc), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"opa eval failed for {rule}:\n{proc.stderr}")
    out = json.loads(proc.stdout)
    results = out.get("result") or []
    if not results:
        return False
    return results[0]["expressions"][0]["value"] is True


def main() -> int:
    args = [a for a in sys.argv[1:]]
    opa = "opa"
    if "--opa" in args:
        i = args.index("--opa")
        opa = args[i + 1]
        del args[i:i + 2]
    initdata = Path(args[0]) if args else ROOT / "initdata.toml"

    raw = initdata.read_bytes()
    rego_text = tomllib.loads(raw.decode("utf-8"))["data"]["policy.rego"]
    rego = ROOT / "test" / ".policy.extracted.rego"
    rego.write_text(rego_text)

    import hashlib
    print(f"policy      {initdata}")
    print(f"sha256      {hashlib.sha256(raw).hexdigest()}")
    print(f"sha384      {hashlib.sha384(raw).hexdigest()}")

    chk = subprocess.run([opa, "check", "--strict", str(rego)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        print("\nFAIL: policy does not compile\n" + chk.stderr, file=sys.stderr)
        return 1
    print("compile     ok (opa check --strict)\n")

    cases = json.loads((ROOT / "test" / "cases.json").read_text())
    failures = []
    for c in cases:
        got = evaluate(opa, rego, c["rule"], c["input"])
        ok = got == c["expect"]
        verdict = "allow" if got else "deny "
        print(f"  {'PASS' if ok else 'FAIL'}  {verdict}  {c['id']:<34} {c['why']}")
        if not ok:
            failures.append(c["id"])

    print(f"\n{len(cases) - len(failures)}/{len(cases)} passed")
    if failures:
        print("failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
