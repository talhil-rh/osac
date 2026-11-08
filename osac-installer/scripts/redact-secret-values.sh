#!/usr/bin/env bash
# Mask credential-bearing values from rendered manifests. `make
# install-dry-run` (and DRY_RUN=1) prints the full rendered manifests to the
# terminal and to collected CI logs, so two value classes are masked:
# Secret `data`/`stringData` payloads (values supplied through values
# overlays, including multi-line block scalars such as PEM keys), and the
# data of the AAP instance-group ConfigMaps (`*-ig`), which carry the
# caller-supplied provisioning endpoint config (EVPN/Netris controller
# URLs and any credential misplaced there instead of the parallel Secret).
# Resource structure, Secret/ConfigMap names and keys, and every other
# resource type stay readable so the dry run remains useful for review.
set -euo pipefail

# Helm renders each resource as a top-level document: kind and the data /
# stringData keys sit at column 0, payload entries one level deeper, block
# scalar bodies deeper still. The document separator resets state so a
# Secret cannot leak its scope into the next document, and any other
# column-0 key ends the payload block.
awk '
/^---$/ { kind = ""; ig_configmap = 0; in_payload = 0; print; next }
/^kind: / { kind = $2; print; next }
/^  name: / {
    if (kind == "ConfigMap" && $2 ~ /-ig$/) ig_configmap = 1
    print; next
}
kind == "Secret" && /^(data|stringData):$/ { in_payload = 1; print; next }
ig_configmap && /^data:$/ { in_payload = 1; print; next }
/^[^ ]/ { in_payload = 0 }
{
    if (in_payload) {
        # Block-scalar body lines (indent deeper than the entry keys) are
        # dropped outright; single-line entry values are masked in place.
        if ($0 ~ /^   +[^ ]/) next
        if ($0 ~ /^  [^ :][^:]*: ./) sub(/: .*/, ": <redacted>")
    }
    print
}
'
