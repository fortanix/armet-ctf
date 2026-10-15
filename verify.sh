#!/usr/bin/env bash
# Independently verify that the node at $HOST is running the measured
# configuration published in this repository.
#
#   HOST=<endpoint> bash verify.sh
#
# <endpoint> is the node's hostname, e.g.
#   HOST=node.example.com bash verify.sh
#
# There is deliberately no default. A verification script that silently checks
# the wrong node is worse than one that refuses to start.
#
# Needs only bash, curl, python3 and sha384sum. No trust in this repository is
# required for the result: the nonce is generated locally, the quote is fetched
# from the node, and the measurements are parsed out of the quote's own bytes.
# This repository supplies one thing -- initdata.toml, the preimage of
# MRCONFIGID -- and the check below is precisely whether that claim holds.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT
# --------------------------------------
# Proves: a genuine Intel TDX quote, freshly bound to YOUR nonce, reports
# MRCONFIGID == SHA-384(initdata.toml) as published here. Since initdata.toml
# contains the Kata agent policy, that fixes the policy the guest is running --
# including `ExecProcessRequest: false` and the image allow-list.
#
# Does NOT prove the container image contents. The image is NOT measured into
# the TD; it is pinned by digest inside the policy, and the policy IS measured.
# So the chain is: quote -> MRCONFIGID -> initdata.toml -> allowed_images ->
# image digest. Verify the last hop yourself with `docker manifest inspect`.
set -uo pipefail
HOST="${HOST:-}"
if [ -z "$HOST" ]; then
    echo "usage: HOST=<endpoint> bash verify.sh" >&2
    echo "  e.g. HOST=node.example.com bash verify.sh" >&2
    echo "  (the node's hostname; there is no default on purpose)" >&2
    exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INITDATA="${INITDATA:-$HERE/initdata.toml}"
# The node may be serving a self-signed certificate while ACME is blocked.
# -k is acceptable HERE and ONLY here: the attestation evidence is bound to a
# nonce you generated, so a man in the middle cannot forge it. Do NOT use -k
# for inference traffic.
CURL=(curl -sS -k -m 30)

ok=0; bad=0
pass() { ok=$((ok+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { bad=$((bad+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

for t in curl python3 sha384sum; do
    command -v "$t" >/dev/null || { echo "need $t"; exit 2; }
done
[ -f "$INITDATA" ] || { echo "no initdata.toml at $INITDATA"; exit 2; }

NONCE="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
echo "host    $HOST"
echo "nonce   $NONCE   (generated locally, not by the node)"
echo

EV="$("${CURL[@]}" "https://$HOST/evidence/cpu?nonce=$NONCE")" || {
    echo "could not reach https://$HOST/evidence/cpu"; exit 1; }

# The checker goes in a FILE, not on stdin.
#
# `python3 - ... <<'PY'` feeds the SCRIPT on stdin, so the script's own
# json.load(sys.stdin) then reads the already-consumed heredoc and dies with
# "Expecting value: line 1 column 1". Both cannot use stdin. Measured
# 2026-10-15 against the live node, which was healthy -- the failure was
# entirely in this script, and it reported it as the NODE being untrustworthy.
# Portable: BSD mktemp accepts -t PREFIX, GNU mktemp demands X's. An
# explicit template works on both.
CHECK="$(mktemp "${TMPDIR:-/tmp}/cvn-verify.XXXXXX")" || { echo "cannot create a temp file"; exit 2; }
trap 'rm -f "$CHECK"' EXIT
cat > "$CHECK" <<'PY'
import base64, hashlib, json, sys, re
nonce, initdata_path = sys.argv[1], sys.argv[2]
body = sys.stdin.read()
try:
    raw = json.loads(body)
except ValueError:
    # A traceback here reads as "the node is broken". Usually it means an
    # HTML error page from something in front of the node, or an empty body.
    print(f"  \033[31mFAIL\033[0m  the response was not JSON ({len(body)} bytes)")
    print(f"        first 120 bytes: {body[:120]!r}")
    sys.exit(1)
# /evidence/cpu nests under "cpu"; /evidence adds a sibling "gpu".
ev = raw["cpu"] if isinstance(raw.get("cpu"), dict) else raw
if raw.get("error") or ev.get("error"):
    print(f"  \033[31mFAIL\033[0m  node returned an error: "
          f"{raw.get('error') or ev.get('error')}")
    sys.exit(1)

# Byte offsets into the TDX quote body (TDREPORT). Hard-coded rather than
# pulled from a library so this script has no dependencies a verifier would
# have to audit.
OFF = {"mrtd": (184, 48), "mrconfigid": (232, 48), "rtmr0": (376, 48),
       "rtmr1": (424, 48), "rtmr2": (472, 48), "rtmr3": (520, 48),
       "report_data": (568, 64)}

q = ev.get("quote")
if not q:
    print("  \033[31mFAIL\033[0m  response carried no quote"); sys.exit(1)
raw = base64.b64decode(q)
if len(raw) < 632:
    print(f"  \033[31mFAIL\033[0m  quote is only {len(raw)} bytes"); sys.exit(1)
m = {k: raw[o:o+n].hex() for k, (o, n) in OFF.items()}

ok = bad = 0
def chk(label, cond):
    global ok, bad
    if cond: ok += 1; print(f"  \033[32mPASS\033[0m  {label}")
    else:    bad += 1; print(f"  \033[31mFAIL\033[0m  {label}")

# 1. Freshness, done the way the node binds it.
#
#    report_data does NOT hold the nonce. The node hashes a binding document
#    {v, nonce, model_id, image_digest, weights_sha384, spki_sha256,
#    spki_origin} and the guest agent copies the 64 ASCII characters of
#    base64(SHA-384(document)) into report_data. Looking for the nonce in
#    report_data therefore always fails.
#
#    Two steps: the quote must commit to the document the node returned, AND
#    that document must carry our nonce. Either alone is insufficient.
rd = bytes.fromhex(m["report_data"])
chk("report_data is not all zeros (an unbound quote)", any(rd))

binding = ev.get("binding")
if not isinstance(binding, dict):
    chk("evidence carries a binding document", False)
else:
    canon = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    want = base64.b64encode(hashlib.sha384(canon).digest()).decode()
    got = rd.decode("ascii", "replace").rstrip("\x00")
    chk("report_data == base64(SHA-384(binding document))", got == want)
    if got != want:
        print(f"        report_data  {got}")
        print(f"        recomputed   {want}")
    chk("the binding document carries OUR nonce (not a replay)",
        (binding.get("nonce") or "").lower() == nonce.lower())

# 2. The claim this repository actually makes.
want = hashlib.sha384(open(initdata_path, "rb").read()).hexdigest()
chk(f"MRCONFIGID == SHA-384(initdata.toml)", m["mrconfigid"] == want)
if m["mrconfigid"] != want:
    print(f"        quote says  {m['mrconfigid']}")
    print(f"        repo gives  {want}")
    print("        The guest is NOT running the configuration published here.")

# 3. The image digest, from two places that must agree.
#
#    (a) initdata.toml -- MEASURED, because MRCONFIGID commits to these bytes.
#    (b) the evidence document's image_digest -- SELF-DECLARED. It reaches
#        report_data via binding_doc(), so it is quote-bound and cannot be
#        changed after the fact. But it originates in CVN_IMAGE_DIGEST, a pod
#        env var, and pod env is NOT measured. The TD has no way to learn its
#        own image digest, so it can only repeat what the host told it.
#
#    Neither alone is worth much. Together they are: (a) is measured and (b) is
#    quote-bound, so a host that substitutes the image must either leave them
#    disagreeing, or change (a) -- which moves MRCONFIGID and breaks check 2.
toml = open(initdata_path).read()
raw = re.findall(r'@(sha256:[0-9a-f:]+)', toml)
good = [d for d in raw if re.fullmatch(r'sha256:[0-9a-f]{64}', d)]
chk("the measured policy names exactly one well-formed image digest",
    len(set(good)) == 1 and len(set(raw)) == 1)
if set(raw) - set(good):
    print(f"        malformed in initdata.toml: {sorted(set(raw) - set(good))}")
    print("        A doubled 'sha256:sha256:' prefix. Note this is NOT merely")
    print("        cosmetic: it is what the cross-check below compares against.")

declared = ev.get("binding", {}).get("image_digest") or ev.get("image_digest")
if declared is None:
    print("  ----  evidence carried no image_digest; cross-check skipped")
else:
    chk("evidence image_digest == the digest measured into MRCONFIGID",
        declared in set(raw))
    if declared not in set(raw):
        print(f"        evidence declares  {declared}")
        print(f"        initdata.toml says {sorted(set(raw))}")
        print("        One of these is wrong. The measured one is authoritative")
        print("        about INTENT; neither is proof of what is running.")

print()
for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mrconfigid"):
    print(f"  {k:12} {m[k]}")
if good:
    print(f"  {'image':12} {good[0]}")
print()
print(f"== {ok} passed, {bad} failed ==")
sys.exit(1 if bad else 0)
PY

printf '%s' "$EV" | python3 "$CHECK" "$NONCE" "$INITDATA"
rc=$?
echo
if [ "$rc" -ne 0 ]; then
    echo "VERIFICATION FAILED. Do not treat this node as running the published"
    echo "configuration."
else
    # Interpolate the real reference. A printed <placeholder> is a shell
    # redirection operator the moment someone pastes it, which is a silly way
    # to lose five minutes at the end of a verification that passed.
    REF="$(grep -o '"[^"]*@sha256:[0-9a-f]\{64\}"' "$INITDATA" | tr -d '"' | head -1)"
    echo "Next, confirm the image digest the measured policy pins is the one you"
    echo "expect to be published:"
    if [ -n "$REF" ]; then
        echo "  docker manifest inspect $REF"
    else
        echo "  (could not read a well-formed image reference from $INITDATA)"
    fi
fi
exit "$rc"
