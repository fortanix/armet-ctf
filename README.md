# Confidential inference node — GLM-5.3-Flash on Intel TDX + NVIDIA PPCIe

A single-tenant inference node serving GLM-5.3-Flash FP8 from inside an Intel
TDX confidential VM, with 8× H200 SXM and 4× NVSwitch in one NVIDIA Protected
PCIe group. Prompts and completions are never readable by the host, the
operator, or anyone with physical access to the machine.

This repository holds everything needed to verify that claim independently: the
guest agent policy that constrains the workload, the `initdata` whose hash is
measured into the attestation report, and the tooling to reproduce and test
both.

Endpoint: `ctf.armet.ai` · TLS terminates **inside** the TD.

---

## Evidence
 
Fetch the quote and read the registers out of it. Do not take these from a
README — including this one:
 
```bash
B=https://ctf.armet.ai
NONCE=$(openssl rand -hex 32)
 
curl -s -H "Authorization: Bearer $KEY" \
  "$B/v1/attestation/report?nonce=$NONCE&model=GLM-5.3-Flash&version=2" \
  > report.json
```
 
```
MRTD        c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c5d7616664fcb190b8eaae2e26d60b12a
RTMR0       b5b6a4094ad7f0723d5227df263144bbd36c2c0859142621cdfce286c06496b8a615aa513ece512bfeb8dd0ac7125419
RTMR1       b767cba3ab019c2c8a9027f87bd81074dcad56e8332d3b5df71edc37fced2915574cf79389aa86922a6e41aa512d26e3
RTMR2       fffc07f5a1762199c0b9c03822dce398ec5737452fdf079636fa7898829d9f9b09bf7666eddf4c73b04171b3dc199d8d
RTMR3       000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
MRCONFIGID  0a51d2f25e55cbba6aedbeaf9aa6f2fad89c99ee16bf896bf37d46845d4ba4b570fe7e454e23e98635cfbf24117fd07b
```
 
| register | meaning |
|---|---|
| `MRTD` | the initial TD measurement — firmware and the TD's initial memory image. Reproducible across hosts for a given stack. |
| `RTMR0` | virtual hardware configuration: memory size, vCPU count, block device driver, device topology. **Per-node.** |
| `RTMR1` | guest kernel. |
| `RTMR2` | kernel command line and initrd. |
| `RTMR3` | unused by design. |
| `MRCONFIGID` | `SHA-384(initdata.toml)` — **this repository's claim.** |


```
docker.io/prabhanjang/cvn-sglang-glm53flash-v523@sha256:d0cb3c45f49a70b31a68cde0bafc5e6a8309ea5d9f2946d4c36ce87fd247847b
``` 

Its digest is pinned by the policy's `allowed_images`, and the in-enclave image
service verifies the manifest digest while pulling, so the running code is
bound to that reference

Model weights are checked separately. The entrypoint hashes `/weights` and
compares against `MODEL_WEIGHTS_SHA384`, baked into the measured image, before
the engine starts. That value is pinned in the policy environment inside
`initdata.toml`, so it is covered by `MRCONFIGID` — the same measurement that
commits the node to this policy also commits it to this set of weights.

```
zai-org/GLM-5.3-Flash   b52f7ca1fbb5a117e621e919b7cc21aefed0dac37fe130ed7286d23c292fd24276400f2f0836aa8767a69ebf927c35a5
```

`weights-manifest.txt` and `weights_digest.sh` make that reproducible from a
public download rather than taken on trust:
 
```bash
# 1. the manifest hashes to the digest pinned in initdata.toml
sha384sum < weights-manifest.txt | awk '{print $1}'
 
# 2. your own download matches the manifest, file by file
cd <your copy of huggingface.co/zai-org/GLM-5.3-Flash>
find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha384sum \
  | diff - weights-manifest.txt && echo IDENTICAL
```

---

## Verifying a live node

| Endpoint | Returns | Auth |
|---|---|---|
| `GET /v1/attestation/report?nonce=<32-64 hex>&model=<name>&version=2` | the full binding document: TDX quote, PPCIe group evidence, TLS key binding | API key |
| `GET /healthz` | liveness | open |


Everything else returns 404. The guest agent's own `/cdh/resource/...`
endpoints are never forwarded.

**Check the channel is the one that was attested.** The quote binds the TLS
public key, so compare it against what your client actually negotiated:

```bash
echo | openssl s_client -connect ctf.armet.ai:443 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -hex | awk '{print $NF}'
 
jq -r '.tls_spki_sha256' report.json
```

If those differ, something is terminating TLS that the quote does not cover.

**`REPORTDATA` does not carry your nonce.** It carries the full v2 digest as 64
ASCII hex characters — a hash binding the nonce, the model id, the TLS SPKI
hash and the NVIDIA evidence payload together. Looking for your nonce inside
`REPORTDATA` will always fail; check the binding instead, by confirming the
digest commits to the nonce you sent and to the SPKI of the connection you are
on. The extraction above decodes it for you.

---

## Guest stack

The confidential guest components — attestation agent, confidential data hub,
and the REST API the guest talks to — are built from Fortanix's public fork:

- source: https://github.com/fortanix/guest-components/tree/beta/0.21.0-fortanix-ccm-0.2.0
- commit: [`d3ae8f2c572e`](https://github.com/fortanix/guest-components/commit/d3ae8f2c572e474d7fd36b76ba4f10042c05fefd)


This is the code that `aa.toml` and `cdh.toml` in `initdata.toml` configure. It
matters for verification because those components are **part of the measured
guest image, not of `MRCONFIGID`**: they land in `RTMR1`/`RTMR2` along with the
kernel, command line and initrd. So `initdata.toml` fixes how they are
configured, and `RTMR1`/`RTMR2` fix what they are.


## Reproducing and testing the policy

```bash
./validate.sh initdata.toml <MRCONFIGID-from-the-quote>
```

Six steps:

1. hashes `initdata.toml` and compares it to the `MRCONFIGID` you pass — take
   that from the TDX quote, not from this README
2. extracts the embedded policy to `measured-policy.rego`, left behind for you
   to read
3. rebuilds `initdata.toml` from the extracted policy and requires the same
   hash back. This proves the extraction lost nothing, **and** that the
   measured bytes contain only that policy plus the two config blocks the
   script declares inline — nothing else is inside the measurement
4. `opa check --strict`
5. runs `policy-tests.py`: three request fixtures built from values measured on
   a live node, which must be **admitted**, then 70 single-mutation cases which
   must each be **refused**
6. prints the forbidden-environment exceptions actually in force

---

## Contents

| File | Purpose |
|---|---|
| `initdata.toml` | its SHA-384 is `MRCONFIGID`, and the policy is embedded in it |
| `validate.sh` | start here: checks the measurement, extracts the policy, proves the extraction exact, tests it |
| `policy-tests.py` | the fixtures and the 70 cases, invoked by step 5 |
| `weights_digest.sh` | the canonical weights-measurement algorithm, as the node runs it |
| `weights-manifest.txt` | per-file SHA-384 of the measured weights; hashes to `MODEL_WEIGHTS_SHA384` |

Requires `opa` and `python3`.

The pod spec's `env` block is a measured interface, not a set of tuning knobs.
Every value in it is pinned, so changing one changes the policy, which changes
`MRCONFIGID` and requires re-registering the measurement. The same is true of
editing a comment in the policy.
