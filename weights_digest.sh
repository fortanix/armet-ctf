#!/usr/bin/env bash
# Canonical weights-measurement algorithm — SINGLE SOURCE OF TRUTH.
#
# Sourced by BOTH:
#   - node/vllm/entrypoint.sh          (in-guest, at boot, gates serving)
#   - build/measure/weights_manifest.sh (on the build host, produces the reference)
#
# If these two ever computed different digests the node would refuse to boot, so
# the algorithm lives in exactly one place and is COPYed into the image. Do not
# reimplement it inline anywhere. build/measure/tests/test_manifest_agreement.sh
# proves the two callers agree on a fixture.
#
# SHA-384, not SHA-256: the digest is extended into a TDX RTMR, which is
# SHA384(RTMR_old ‖ extend_data) over a 48-byte extend_data. A 48-byte SHA-384
# digest drops in unpadded; a 32-byte SHA-256 digest does not.

# Algorithm (two-stage, order-independent of the filesystem):
#   1. enumerate every regular file under <dir>, NUL-delimited
#   2. byte-sort that list under LC_ALL=C           <- kills readdir-order variance
#   3. sha384sum each file -> "<hex>  <relpath>" lines
#   4. sha384sum that stream -> one 96-hex-char digest
#
# Paths are relative to <dir> (we cd first), so the digest is invariant to the
# mount point: the same bytes measured at /weights/X and at /tmp/fixture agree.

CVN_DIGEST_RE='^[0-9a-f]{96}$'

# cvn_weights_manifest <dir>  -> emits the "<sha384>  <relpath>" lines on stdout.
# This is stage 1-3. Kept separate so weights_manifest.sh can save the per-file
# manifest for auditors without recomputing.
cvn_weights_manifest() {
  local dir="$1"

  [[ -n "${dir}" ]]   || { echo "cvn_weights_manifest: no directory given" >&2; return 2; }
  [[ -e "${dir}" ]]   || { echo "cvn_weights_manifest: ${dir} does not exist" >&2; return 2; }
  [[ -d "${dir}" ]]   || { echo "cvn_weights_manifest: ${dir} is not a directory" >&2; return 2; }

  # Reject anything that is not a directory or a regular file. A symlink, device
  # node or FIFO in the tree is either an unmeasured file (symlinks are skipped
  # by -type f, so their contents would never enter the digest) or a way to point
  # the measured set at bytes outside the mount. Fail loudly instead of silently
  # measuring less than what is there.
  #
  # Consequence, deliberate: /weights must be a materialised tree, not a
  # HuggingFace snapshot symlink farm (snapshots/<rev>/*.safetensors -> ../../blobs/).
  # An HF cache layout hashes to the empty-set digest under -type f, which is
  # exactly the silent failure this check converts into a hard error.
  local stray
  stray="$(cd "${dir}" && find . ! -type d ! -type f -printf '%y %p\n' 2>/dev/null | head -20)"
  if [[ -n "${stray}" ]]; then
    echo "cvn_weights_manifest: ${dir} contains non-regular entries; refusing to measure a partial set:" >&2
    printf '  %s\n' "${stray}" >&2
    return 3
  fi

  # Count first. This is NOT redundant with `xargs -r`.
  #
  #   find <empty> -print0 | sort -z | xargs -0 sha384sum | sha384sum
  #
  # yields a perfectly well-formed digest and exit status 0 for an EMPTY tree:
  # with no arguments sha384sum reads stdin, and even with `xargs -r` suppressing
  # the call entirely the final sha384sum still hashes an empty stream. Either way
  # an unmounted or empty /weights produces a stable, plausible-looking digest
  # rather than an error. Only an explicit count catches it.
  local n
  n="$(cd "${dir}" && find . -type f -printf '.' | wc -c)"
  if [[ "${n}" -eq 0 ]]; then
    echo "cvn_weights_manifest: ${dir} contains no regular files — not mounted?" >&2
    return 4
  fi

  # Every regular file is measured; there is no extension filter. A filter that
  # admitted only *.safetensors/*.json/*.model would leave config .py (executed
  # under trust_remote_code), chat templates (.jinja — they drive tool parsing),
  # merges.txt and tokenizer blobs outside the measurement while the digest still
  # looked authoritative. "Which model actually loaded" has to mean all of it.
  ( cd "${dir}" && find . -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 -r sha384sum )
}

# cvn_weights_digest <dir> -> the single 96-hex-char manifest digest (stage 4).
cvn_weights_digest() {
  local dir="$1" out

  # `|| rc=$?` is the only form that both suspends errexit AND preserves the
  # real status. Two traps avoided here:
  #   - a bare assignment aborts the shell under `set -e` before any rc check;
  #   - `if ! out=$(...); then return $?; fi` returns 0, because inside the
  #     branch $? is the status of the NEGATED pipeline (i.e. 0 when the command
  #     failed), so the caller sees success and an empty digest.
  # Also note `local x="$(...)"` swallows the status entirely even under
  # pipefail — the status becomes the declaration builtin's. `local` is declared
  # separately above for exactly that reason.
  local rc=0
  out="$(cvn_weights_manifest "${dir}" | sha384sum | awk '{print $1}')" || rc=$?
  if (( rc != 0 )); then return "${rc}"; fi

  [[ "${out}" =~ ${CVN_DIGEST_RE} ]] || {
    echo "cvn_weights_digest: computed value is not a SHA-384 digest: '${out}'" >&2
    return 5
  }
  printf '%s\n' "${out}"
}
