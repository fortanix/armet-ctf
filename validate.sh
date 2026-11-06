#!/usr/bin/env bash
# =============================================================================
# Independent validation of this node's guest agent policy.
#
#   ./validate.sh initdata.toml <expected-MRCONFIGID>
#   ./validate.sh initdata.toml                    # prints the hash to compare
#
# ONE artifact has to be trusted: initdata.toml. Its SHA-384 *is* the
# MRCONFIGID in the TDX attestation report, and the policy the guest agent
# enforces is embedded inside it. Everything checked below is extracted from
# that file, so there is no second copy of the policy that could drift away
# from the measured one.
#
# Take the expected MRCONFIGID from the quote (GET /evidence/cpu), not from
# this repository. A hash published next to the file it measures proves
# nothing.
#
# Needs: opa, python3, sha384sum.
# =============================================================================
set -uo pipefail
IN=${1:-initdata.toml}
WANT=${2:-}
HERE=$(cd "$(dirname "$0")" && pwd)
fail=0

for t in sha384sum opa python3; do
    command -v "$t" >/dev/null || { echo "FATAL: $t not on PATH" >&2; exit 1; }
done
[ -f "$IN" ] || { echo "FATAL: $IN not found" >&2; exit 1; }
[ -f "$HERE/policy-tests.py" ] || { echo "FATAL: policy-tests.py not found" >&2; exit 1; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

# The initdata layout, inlined so step 3 can rebuild it. This doubles as a
# declaration of what the measurement is ALLOWED to contain: one policy and
# exactly these two config blocks. If the round trip matches, nothing else is
# inside the measured bytes.
rebuild_initdata() {   # $1 = policy file, $2 = output
    cat > "$2" <<EOF
version = "0.1.0"
algorithm = "sha384"
[data]
"policy.rego" = '''
$(cat "$1")
'''
"aa.toml" = '''
[token_configs.ccm_as]
ccm_domain_names = ["fortanix.com"]
'''
"cdh.toml" = '''
[kbc]
name = "ccm_kbc"
url = "https://apps.amer.smartkey.io"
[kbc_configs.ccm_kbc]
dsm_app_id = "22b1bc64-a371-438d-af30-d714dfc212cb"
'''
EOF
}

echo "== 1. the measurement =="
got=$(sha384sum "$IN" | cut -d' ' -f1)
echo "   sha384($IN)"
echo "     $got"
if [ -n "$WANT" ]; then
    if [ "$got" = "$WANT" ]; then
        echo "   MATCHES the expected MRCONFIGID"
    else
        echo "   MISMATCH - expected:" >&2
        echo "     $WANT" >&2
        echo "   This file is not what the node registered. Stop here." >&2
        exit 1
    fi
else
    echo "   No expected value given. Compare this against MRCONFIGID in the"
    echo "   TDX quote from /evidence/cpu before trusting anything below."
fi

echo "== 2. extract the policy that was measured =="
python3 - "$IN" "$W" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r'"policy\.rego" = \'\'\'\n(.*?)\n\'\'\'', s, re.S)
if not m:
    sys.exit("FATAL: no policy.rego literal in this initdata")
if "package agent_policy" not in m.group(1):
    sys.exit("FATAL: the extracted block is not an agent policy")
open(sys.argv[2] + "/measured-policy.rego", "w").write(m.group(1) + "\n")
print("   extracted %d bytes" % (len(m.group(1)) + 1))
PY
[ $? -eq 0 ] || { echo "FATAL: could not extract the policy" >&2; exit 1; }
[ -s "$W/measured-policy.rego" ] || { echo "FATAL: extracted policy is empty" >&2; exit 1; }
POL="$W/measured-policy.rego"
cp "$POL" ./measured-policy.rego          # left behind so you can read it

echo "== 3. prove the extraction is faithful and complete =="
rebuild_initdata "$POL" "$W/rt.toml"
back=$(sha384sum "$W/rt.toml" | cut -d' ' -f1)
if [ "$back" = "$got" ]; then
    echo "   rebuilding from the extracted policy reproduces the same sha384."
    echo "   The extraction lost nothing, and the measured bytes hold nothing"
    echo "   but that policy and the two config blocks declared above."
else
    echo "   ROUND TRIP FAILED" >&2
    echo "     original: $got" >&2
    echo "     rebuilt:  $back" >&2
    echo "   Either the extraction is lossy or initdata.toml carries data" >&2
    echo "   beyond the policy and the declared config. Inspect it by hand." >&2
    exit 1
fi

echo "== 4. the measured policy compiles =="
if opa check --strict "$POL"; then echo "   PASS"; else echo "   FAIL" >&2; exit 1; fi

echo "== 5. the measured policy behaves =="
python3 "$HERE/policy-tests.py" "$POL" || fail=1

echo "== 6. the forbidden-environment exceptions actually in force =="
echo "   (a deliberate relaxation; see the README)"
opa eval -f pretty -d "$POL" 'data.agent_policy.forbidden_env_exceptions'

echo
if [ "$fail" = 0 ]; then
    echo "VALIDATION PASSED"
    echo "The policy measured into MRCONFIGID is the policy tested above."
    echo "It is left in ./measured-policy.rego for you to read."
else
    echo "VALIDATION FAILED - see above" >&2
    exit 1
fi
