# Confidential AI node — attestation reference

GLM-5.3-Flash served from inside an **Intel TDX** confidential VM on 8x NVIDIA
H200 SXM with 4x NVSwitch in **PPCIe** (Protected PCIe) mode.

This repository publishes the one input a third party cannot otherwise obtain:
`initdata.toml`, the byte-exact preimage of the TD's `MRCONFIGID`. Everything
else here can be derived from it or read out of a quote you fetch yourself.

## Verify it yourself

```
git clone https://github.com/fortanix/armet-ctf && cd armet-ctf
ENDPOINT=the-node-hostname          # e.g. node.example.ai
HOST="$ENDPOINT" bash verify.sh
```

`verify.sh` generates its own nonce, fetches a fresh TDX quote from the node,
parses the measurements out of the quote's bytes, and checks that

```
MRCONFIGID == SHA-384(initdata.toml)
```

## Deriving MRCONFIGID

```
$ sha384sum initdata.toml
6f5e1772e33b2226886d34cca4177fde87f491da4d433de72970aded14beb250d65270251b446c90560855b7f979dc5d  initdata.toml
```

This works because the host passes `initdata.toml` to the guest and the TD
measures **SHA-384 over those exact bytes** into `MRCONFIGID`. 

- **The policy is inside the measurement.** `initdata.toml` embeds
  `policy.rego`, so the TD's `MRCONFIGID` commits to the Kata agent policy —
  including `ExecProcessRequest: false` and the image allow-list. That is what
  makes the next section meaningful.

## Evidence

```
MRTD         c78e2b8b2f66207f3807d8d999f51e04f5eab8f7aa02614a86ddd81b61f4e79c5d7616664fcb190b8eaae2e26d60b12a
RTMR0        cfdae1db22a9f72f220b732a7de45bd5295a568451ee5309906c248dd70cde858adbd7693542bfd5edf3e0eed56a88b7
RTMR1        b767cba3ab019c2c8a9027f87bd81074dcad56e8332d3b5df71edc37fced2915574cf79389aa86922a6e41aa512d26e3
RTMR2        fffc07f5a1762199c0b9c03822dce398ec5737452fdf079636fa7898829d9f9b09bf7666eddf4c73b04171b3dc199d8d
RTMR3        000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
MRCONFIGID   6f5e1772e33b2226886d34cca4177fde87f491da4d433de72970aded14beb250d65270251b446c90560855b7f979dc5d
```

| register | meaning |
|---|---|
| `MRTD` | the initial TD measurement — firmware and the TD's initial memory image. Reproducible across hosts for a given stack. |
| `RTMR0` | virtual hardware configuration: memory size, vCPU count, block device driver, device topology. **Per-node.** |
| `RTMR1` | guest kernel. |
| `RTMR2` | kernel command line and initrd. |
| `RTMR3` | unused by design. |
| `MRCONFIGID` | `SHA-384(initdata.toml)` — this repository's claim. |


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

## Image

```
docker.io/prabhanjang/cvn-vllm-glm53flash@sha256:9d0fda256d3bcfe8381f0fdc3fde5ef8e24a1cc12ded0ac20011d19a38916a09
```

Two of the image's layers are **encrypted**, and that is checkable by anyone
without credentials to this node:

```
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:prabhanjang/cvn-vllm-glm53flash:pull" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $TOKEN"   -H 'Accept: application/vnd.oci.image.manifest.v1+json'   "https://registry-1.docker.io/v2/prabhanjang/cvn-vllm-glm53flash/manifests/sha256:9d0fda256d3bcfe8381f0fdc3fde5ef8e24a1cc12ded0ac20011d19a38916a09"   | python3 -c 'import sys,json; m=json.load(sys.stdin); print("layers", len(m["layers"]), "encrypted at", [i for i,l in enumerate(m["layers"]) if "enc" in l["mediaType"]])'
```

The decryption key lives in a Fortanix DSM security object and is released
through the Confidential Data Hub only after CCM has verified this TD's
measurements against the registered build. A substituted image does not obtain
that key and cannot be unpacked.

Proves: a genuine TDX quote, bound to your nonce, reports an `MRCONFIGID` equal
to the SHA-384 of the `initdata.toml` published here. The guest is therefore
running this agent policy, with exec denied and image pulls restricted to the
pinned digest.


