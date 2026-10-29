# Agent policy - sample

**Artifact under review:** `initdata.toml`
**Running on:** the SEV-SNP rehearsal node, admitting a live pod at time of writing

---

## What we are asking

Reviewing the policy to check if this rule set meets security criteria. If it does, 
we will regenerate the tables against the production node and deploy once.

The file has two halves and they warrant different scrutiny:

- **Rules** — the admission logic. These carry the security properties and
  port to production unchanged. This is what we want reviewed.
- **Tables** — environment, mounts, capabilities, devices, storages, masked
  paths. Node-specific data, derived from live requests on the rehearsal node.
  Every one is regenerated from the production node's own requests, so
  reviewing their contents here tells you little.

---

## 1. Earlier findings

| # | Finding | Status |
|---|---|---|
| 1 | Verifier accepts a fabricated quote | verify.sh is just a script to get evidence from production system and match it with published measurements. |
| 2 | Storage restrictions bypassable; `CreateSandboxRequest` accepts arbitrary storages | **Fixed**, reproduced first |
| 3 | File-copy rules do not check symlink targets or file type | **Fixed** |
| 4 | `pause_image` undefined, `rego_unsafe_var_error` | **Explained** |

### Finding 2 — reproduced, then fixed

A storage mounted at `/run/kata-containers/sandbox/ephemeral/../../../../etc`
returned `CreateContainerRequest = true`. The cause was a wildcard tail in the
mount-point pattern — `(shm|ephemeral/.+)`, where `.+` matches a climb out of
the directory it names.

Fixed by removing wildcard tails entirely; adding a `path_sane` guard that
refuses relative paths, parent-directory segments, empty segments and
backslashes; and pinning **driver, filesystem type, source, mount point and
mount options** per row rather than the mount point alone. The `local` driver
was dropped — nothing uses it. `CreateSandboxRequest` now runs the same check.

### Finding 3 — fixed

A permitted filename is not a permitted file.
The request turned out to carry `file_type` and `symlink_target` as explicit
fields, so the check reads them directly rather than inferring from the mode.
`file_type` must be `"Regular"` and the link target must be empty or null. A
request claiming `Regular` while carrying a link target is refused, so the two
cannot be played against each other.

### Finding 4 — explained

Every Kubernetes pod has a sandbox container. It is created by containerd from
its own configured image and never appears in the pod spec, which is why it was
believed absent. Production uses `registry.k8s.io/pause:3.10.1`, confirmed from
`containerd config dump`.

Removing the rule rather than correcting the value would reopen the hole 
identified earlier: matching on command line and user alone
admits an arbitrary image into the pod's network namespace.

### One we found while fixing earlier comments

`sandbox_pidns` was unchecked in both request types. With a shared PID
namespace, any container in the pod reads the inference process through
`/proc` — its command line, its memory maps, and with the right capability its
memory. Now pinned false in all three rules.

---

## 2. What the policy enforces

Nothing is admitted by default. Each rule body is a conjunction, and a
restriction is added as a line inside an existing body — never as a new rule,
since rules sharing a name are combined with OR.

| Request | Enforced |
|---|---|
| `CreateContainerRequest` | Separate exact rules for the workload and the sandbox container, each identified by command line, user and the container type the runtime reports. Exact environment, exact mounts with exact option sets, exact capabilities, no hooks, no devices, no seccomp profile, pinned kernel parameters, pinned masked and read-only paths, pinned root read-only flag, PID namespace not shared. |
| Root filesystem | Must be the pinned image digest **and** the filesystem the container is actually rooted on: the storage mount point and `OCI.Root.Path` are both bound to the request's own `container_id`. The image reference is checked in `source` and again in the storage's driver options, under each container type's own key. Exactly one root filesystem, so a second cannot ride alongside. |
| `CreateSandboxRequest` | Denied by default. Admitted only with an empty guest hook path, no kernel modules, PID namespace not shared, and storages held to the same table and path rules. |
| `CopyFileRequest` | Four orchestrator-owned filenames at the per-sandbox paths the runtime generates, plus `file_type` `Regular`, an empty link target, and a mode from the enumerated set of regular-file modes carrying no execute, setuid, setgid or sticky bit. |
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
attested code does without altering the image: loader preloads and library
paths, interpreter paths and startup files, shell initialisation, and the JVM
and Node equivalents. The exact-environment rule already refuses anything
outside the allowed set; this catches an error in that set.

---

## 3. Evidence

Four positives admitted and **65 adversarial cases denied**, evaluated offline
under OPA against inputs reconstructed from live agent requests, then confirmed
on the node: the pod starts, and `kubectl exec` is refused by the agent with
`ExecProcessRequest is blocked by policy`.

| Group | Cases | Covers |
|---|---|---|
| Container spec | 34 | extra / altered / removed / duplicate environment entries, loader preload, mount over the attested code, extra volume, dropped mount option, stacked duplicate mount, forged source path, replaced command, non-root user, changed working directory, container type spoofed, hook added, device added, capability added, ambient capability, masked or read-only path removed, kernel parameter added, privilege escalation re-enabled, seccomp set, root path elsewhere, mount point not matching the container id, driver options disagreeing with `source`, driver options absent, wrong digest, tag instead of digest, a different image, two root filesystems, shared, extra overlay options, host device, resource limit added |
| Storage escape | 7 | parent-directory escape on two drivers, swapped filesystem type, unconstrained source, a driver outside the table, empty path segment, storage over a protected path |
| Shared PID namespace | 1 | `sandbox_pidns` true |
| File copy | 17 | symbolic link by target, symbolic link by mode, directory, executable, setuid, missing type field, traversal, filename outside the permitted four, null and absent target encodings |
| Sandbox request | 6 | guest hook path set, kernel module, shared PID namespace, extra storage, altered storage options, path escaping the sandbox directory |

The storage-escape and file-copy groups are the direct regression tests for
 findings 2 and 3.
---

## 4. Reproducing it

```bash
# extract the policy from the TOML
python3 -c "
import tomllib
print(tomllib.load(open('initdata.toml','rb'))['data']['policy.rego'])" > policy.rego

opa check policy.rego
opa eval -d policy.rego -i <request>.json 'data.agent_policy.CreateContainerRequest'
```

Validated with OPA 0.70.0. Note that the guest enforces with regorus, not OPA;
constructs that pass `opa check` are not guaranteed to behave identically
there, which is why every rule here was also confirmed against a live agent.
