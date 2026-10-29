# Armet CVN — agent policy, revision 2

**Date:** 29 October 2026
**Artifact under review:** `initdata.toml` in this directory
**Previous round:** commit `6bce817b`

```
sha256   30e71ff93e19014c0bf76a409b394ce5e6a2ffd64ed094ba6de5cc4188861d3c
sha384   7d0721afdc3a5b63c9d7e1a914bab8fee6afb299c334b1cf8ca037bad82dafd36b82389d2b57e137b65bfaa43e69dae7
bytes    33455
```

On the SEV-SNP rehearsal node the digest algorithm is **sha256**, bound into
`HOST_DATA`. On the TDX production node it is **sha384**, bound into
`MRCONFIGID`. Both digests are printed above so that either can be checked
against the measurement register without re-deriving them.

### Validation status

| | |
|---|---|
| Compiles under `opa check --strict`, OPA 0.70.0 | **yes** |
| Regression suite, 14 cases | **14/14 pass** |
| Same suite re-run on the rehearsal node | **14/14 pass** |
| Admitted a live pod on the rehearsal node | **yes**, 29 October 2026 |
| Same suite against the previous revision | **6 fail** — it reproduces your findings 2a and 2b |

The six failures on the previous revision are how we know the cases test
something rather than passing vacuously. They are listed in §2.

---

## 1. Your findings

| # | Finding | Status |
|---|---|---|
| 1 | Published policy fails to compile; `not_a_symlink` missing | **Accepted.** Publication defect, not a policy defect — §1.1 |
| 2a | Sandbox rule accepted an unapproved image source | **Accepted and fixed** — §1.2 |
| 2b | Image-options check accepted contradictory JSON | **Accepted and fixed** — §1.3 |
| 3 | CCM clarification valid; evidence requirements stated | **Accepted** — §4 |

### 1.1 The published file was not the file that booted

You are right, and the diagnosis is worse than a missing rule: the two lines
defining `not_a_symlink` were lost between the artifact we tested and the
commit we published. The rule is present in the file that admitted the pod.
Your conclusion holds regardless — a policy that does not compile cannot be
the policy that admitted anything, so whatever you reviewed was never what we
ran. That is our error and the review cost you should not have paid.

Two changes so it cannot recur:

- `opa check --strict` is now a gate in `test/run-policy-tests.py`, which
  refuses to run the suite at all if the policy does not compile. It would
  have caught this in under a second.
- The harness prints the digest of the `initdata.toml` it tested, so the
  published file, the tested file and the measurement register can be compared
  without trusting a claim about them.

We know `opa check` passing does not prove the guest's regorus engine accepts
the same file. It is a one-way gate: failing is decisive, passing is not.

The digest check earned its place immediately. The first copy of this revision
to reach the node hashed to `ec90c57c…` rather than the digest above, because
a transfer had stripped the file's final newline. The content was identical —
`head -c -1` on our copy reproduces that digest exactly — but the measurement
was not, and a file whose digest changes when an editor saves it is a poor
thing to bind into an attestation report. The artifact published here is the
newline-terminated one, and it is the one the node ran.

### 1.2 The sandbox path accepted an unapproved image source

Confirmed. The storage table matched `source` against a character-class
pattern:

```rego
"source": `^[A-Za-z0-9][A-Za-z0-9@:/._-]{0,250}$`
```

which is a shape, not a restriction, on a field whose only purpose is to name
one specific thing. On the container path `workload_rootfs_pinned` re-pinned
it to an allowed digest afterwards. **`CreateSandboxRequest` had no equivalent
backstop**, so any well-formed reference was admitted there. Since guest pull
resolves the image from exactly that field, this is closer to reachable than
theoretical.

Fixed by making the source an exact set and splitting the two request paths,
which were previously sharing one table:

```rego
container_image_sources := {s | some s in array.concat(allowed_images, ["pause"])}

container_allowed_storages := [
    {"driver": "image_guest_pull", "fstype": "overlay",
     "mount_point": rootfs_mount_point,
     "sources": container_image_sources, "options": set()},
    shm_storage,
]

sandbox_allowed_storages := [
    {"driver": "image_guest_pull", "fstype": "overlay",
     "mount_point": rootfs_mount_point,
     "sources": {"pause"}, "options": set()},
    shm_storage,
]
```

`storage_allowed` now takes the table as an argument, so the two call sites
cannot silently converge again. The container path admits either container's
root filesystem and `workload_rootfs_pinned` / `pause_rootfs_pinned` then
decide which; the sandbox path can only ever carry the infrastructure
container's. This runtime reports that filesystem with the literal source
`"pause"` rather than an image reference, which is why that string appears in
both sets.

Regression cases: `S2-sandbox-unapproved-image`,
`S3-sandbox-carries-workload-image`, `C2-container-unapproved-image`.

### 1.3 The driver-options check accepted contradictory JSON

Confirmed, and it was two holes rather than one. The check was:

```rego
some opt in object.get(s, "driver_options", [])
contains(opt, concat("", [`"io.kubernetes.cri.image-name":"`, img, `"`]))
```

A substring test over a JSON document accepts an entry naming the approved
image **and** another one. Duplicate keys resolve last-wins in Go and
first-wins in several other decoders, so the policy and the service that
consumes the entry can reach different conclusions about which image is being
pulled, and nothing reports the disagreement. Separately, `some opt in …`
constrains one entry of the list and leaves every other entry unexamined.

Replaced with three requirements, each closing one hole:

```rego
driver_options_pinned(s, key, img) if {
    opts := object.get(s, "driver_options", [])
    count(opts) == 1
    some opt in opts
    marker := concat("", [`"`, key, `":"`])
    count(split(opt, marker)) == 2
    contains(opt, concat("", [marker, img, `"`]))
}
```

Exactly one entry; the key occurs exactly once within it, so a repeated key is
refused rather than resolved; and that one occurrence is followed by the
approved reference. Both container types call it with their own key.

Regression cases: `W2-options-duplicate-key`, `W3-options-second-entry`,
`W4-options-other-image`, `P2-pause-duplicate-key`.

**What this still does not establish.** It constrains the one key we have
observed the image service reading. If the entry carries a second field that
the service prefers, this check would not see it. The stronger form is exact
set equality against the complete `driver_options` value read from a live
request; we will adopt it once we have confirmed that value is stable across
restarts, and we would rather say so than imply a guarantee we have not
earned.

---

## 2. The regression suite

`test/run-policy-tests.py` extracts the Rego from the measured TOML, gates on
`opa check --strict`, then evaluates each case in `test/cases.json`. It needs
only `opa` and Python 3.11.

```
$ ./test/run-policy-tests.py
policy      initdata.toml
sha256      30e71ff93e19014c0bf76a409b394ce5e6a2ffd64ed094ba6de5cc4188861d3c
sha384      7d0721afdc3a5b63c9d7e1a914bab8fee6afb299c334b1cf8ca037bad82dafd36b82389d2b57e137b65bfaa43e69dae7
compile     ok (opa check --strict)

  PASS  allow  N1-symlink-empty              an empty symlink_target means the file is not a link
  PASS  deny   N2-symlink-set                a populated symlink_target must be refused
  PASS  allow  N3-symlink-null               the runtime sends null when the field is absent
  PASS  allow  S1-sandbox-legitimate         ...
  PASS  deny   S2-sandbox-unapproved-image   REGRESSION: the shape pattern admitted any well-formed reference here
  PASS  deny   S3-sandbox-carries-workload-image
  PASS  allow  C1-container-legitimate
  PASS  deny   C2-container-unapproved-image
  PASS  allow  W1-options-clean
  PASS  deny   W2-options-duplicate-key      REGRESSION: a substring test passed this
  PASS  deny   W3-options-second-entry       REGRESSION: a second entry went unexamined
  PASS  deny   W4-options-other-image
  PASS  allow  P1-pause-clean
  PASS  deny   P2-pause-duplicate-key

14/14 passed
```

Point it at the previous revision and six of them fail, which is how we know
the cases test something rather than passing vacuously. That revision is
committed here so the result is reproducible:

```
$ ./test/run-policy-tests.py test/previous/initdata-402de03b.toml
sha256      402de03bc0a3963084aa73b8880bcc95498b6bfe49c7394432897db613de4636
compile     ok (opa check --strict)
...
8/14 passed
failed: S2-sandbox-unapproved-image, S3-sandbox-carries-workload-image,
        C2-container-unapproved-image, W2-options-duplicate-key,
        W3-options-second-entry, P2-pause-duplicate-key
```

Use that file rather than commit `6bce817b` for this comparison. `6bce817b`
stops at the compile gate, because it is the copy whose two defining lines for
`not_a_symlink` were lost — the defect in your finding 1. `402de03b…` is the
revision that actually ran, it contains the rule, and hashing it is the
simplest way to confirm that claim without taking our word for it.

The cases exercise rule logic against crafted agent requests, which is the
level your findings live at. They do not replace booting the policy: OPA and
regorus are different implementations, and only the one inside the guest is
authoritative. The pod-level suite from the previous round — 4 positives and
65 adversarial pod specs on the node — still applies and is unchanged.

The `driver_options` strings in the fixtures are synthetic. They carry the key
and the reference in the shape we have observed; they are not copied from a
live request, and the exact-equality upgrade in §1.3 is what removes that
caveat.

---

## 3. What the policy enforces

Nothing is admitted by default. Each rule body is a conjunction, and a
restriction is added as a line inside an existing body — never as a new rule,
since rules sharing a name are combined with OR.

| Request | Enforced |
|---|---|
| `CreateContainerRequest` | Separate exact rules for the workload and the infrastructure container, each identified by command line, user and the container type the runtime reports. Exact environment, exact mounts with exact option sets, exact capabilities, no hooks, no devices, no seccomp profile, pinned kernel parameters, pinned masked and read-only paths, pinned root read-only flag, PID namespace not shared. |
| Root filesystem | Must be the pinned image **and** the filesystem the container is actually rooted on: the storage mount point and `OCI.Root.Path` are both bound to the request's own `container_id`. The reference is checked in `source` and again in the driver options under each container type's own key, with the constraints in §1.3. Exactly one root filesystem, so a second cannot ride alongside. |
| `CreateSandboxRequest` | Denied by default. Admitted only with an empty guest hook path, no kernel modules, PID namespace not shared, and storages held to `sandbox_allowed_storages` and the path rules. |
| `CopyFileRequest` | Four orchestrator-owned filenames at the per-sandbox paths the runtime generates, plus `file_type` `Regular`, an empty or null link target, and a mode from the enumerated set of regular-file modes carrying no execute, setuid, setgid or sticky bit. |
| `ExecProcessRequest` | Denied. |
| `SetPolicyRequest` | Denied — the rules cannot be replaced after boot. |
| Also denied | Writing to the workload's input, reseeding the guest random device, pausing or resuming the container, adding swap, tracing, changing the filesystem view or the container spec after admission, moving the guest clock, extracting diagnostic data. |
| `ReadStreamRequest` | **Allowed, deliberately** — see §6. |

Two guards sit outside the tables and are the ones we would most like
challenged.

**Protected prefixes.** No mount and no storage may be placed at or beneath the
paths holding the attested code, the dynamic loader's configuration, or the
account databases — whatever the mount table says. This is the independent
guard against the cheapest attack available to an operator: substituting code
while the image digest, the command line and every hardware measurement stay
identical.

**Forbidden environment names.** A second barrier behind the exact-environment
rule, listing 35 documented ways to execute different code or redirect what the
attested code does without altering the image. The exact-environment rule
already refuses anything outside the allowed set; this catches an error in that
set.

---

## 4. Your finding 3 — what we can bind, and what we cannot

Thank you for separating the helper script from CCM. You are right that the
fabricated-quote result showed our checker was insufficient, not that CCM
accepts forged attestation.

Your requirement reads as four bindings. Three are available now; one is not,
and we would rather be explicit than quietly omit it.

**Policy — already bound, and possibly not obviously so.** The measurement
register *is* the policy binding. `HOST_DATA` on SNP is sha256 of this exact
`initdata.toml`, and `MRCONFIGID` on TDX is sha384 of it. Both digests are at
the top of this document. No separate policy attestation is needed; the
derivation is the proof, and the harness recomputes it so the committed file
and the register can be compared directly. Had this check existed, your
finding 1 would have been caught by us rather than by you.

**Measurements — available.** MRTD and RTMR0–3 on the production node are
recorded against each release, and `RTMR0` moves with the trusted domain's
memory size, which we track as a release variable rather than a surprise.

**Serving TLS key — available.** `tls_spki_sha256` is one of the two documented
`channel_binding` types, and the key it binds is generated inside the trusted
domain and never exported. Freshness comes from the nonce on the attestation
endpoint, with sessions carrying an explicit expiry.

**GPU attestation — not available, and we will not claim it.** `gpu_attested`
has a permitted value of `Unknown`, and that is the honest status today:
nvtrust issue #153 leaves NVSwitch evidence unusable under PPCIe, and our four
switches are in one protected group. We can assert that the GPUs are in
confidential-compute mode; we cannot produce verifiable NVSwitch evidence. If
your criteria require it, that is a gate we do not currently pass, and we would
rather discover that now.

We would still welcome a view on the route for the verifier itself: verifying
the signed token our attestation service issues — signature, measurement
claims, TCB status, our nonce — or verifying locally against the AMD key
distribution service rather than parsing quotes by hand.

---

## 5. Known gaps

Stated so you do not have to find them.

**Container output stays readable by the operator, deliberately.** In this
runtime the host draining the output stream is the only thing that empties it;
refusing the read fills the buffer and stalls every process inside the enclave
that writes to it. We measured this — the workload froze mid-start and the
probe killed it fifty minutes later. Confidentiality comes from controlling
what reaches the stream instead: the exact-environment rule makes debug and
request logging unreachable, because the variables that would enable them
cannot be set at all. The claim is that container logs carry operational
metadata only, no prompts and no completions, and that is checkable directly
against the output.

**`dns` and `hostname` in the sandbox request are unconstrained.** The host can
set the enclave's resolvers. We have not pinned them because we have not yet
observed their format, and we would rather leave a known gap than guess at a
value and discover the guess refuses the pod.

**The `driver_options` pin is structural, not exact.** See the end of §1.3.

**The policy does not cover availability, network configuration, or the content
of the model loaded at runtime.** The host can stop the pod. The host is the
hypervisor and owns the network, which is why traffic protection rests on
terminating TLS inside the enclave with a key generated there and never
exported. Model integrity is verified by the workload itself — the policy's
contribution is guaranteeing the code doing the verifying is the attested code,
which is what makes decision 4 matter.

---

## 6. Layout

```
initdata.toml                            the measured artifact
test/run-policy-tests.py                 compile gate + 14 regression cases
test/cases.json                          the cases, as rule / input / expected verdict
test/extract-policy.py                   pulls [data]."policy.rego" out of the TOML
```

Requires OPA — pin **v0.70.0**, the version you tested with — and Python 3.11
or newer.

```
curl -sSL -o ~/bin/opa \
  https://openpolicyagent.org/downloads/v0.70.0/opa_linux_amd64_static
chmod +x ~/bin/opa
```