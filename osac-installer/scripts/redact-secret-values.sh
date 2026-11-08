#!/usr/bin/env bash
# Mask Secret payload values from rendered manifests. `make install-dry-run`
# (and DRY_RUN=1) prints the full rendered manifests to the terminal and to
# collected CI logs; those manifests can carry credential values supplied
# through values overlays, so only Secret data/stringData payloads are
# masked. Resource structure, Secret names and keys, and every other
# resource type stay readable so the dry run remains useful for review.
set -euo pipefail

# Helm renders each resource as a top-level document: kind and the data /
# stringData keys sit at column 0, payload entries one level deeper. The
# document separator resets state so a Secret cannot leak its scope into
# the next document, and any other column-0 key ends the payload block.
awk '
/^---$/ { in_secret = 0; in_payload = 0; print; next }
/^kind: Secret$/ { in_secret = 1; print; next }
in_secret && /^(data|stringData):$/ { in_payload = 1; print; next }
/^[^ ]/ { in_payload = 0 }
in_payload && /^  [^ :][^:]*: ./ { sub(/: .*/, ": <redacted>") }
{ print }
'
