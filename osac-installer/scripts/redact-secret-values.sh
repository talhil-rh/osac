#!/usr/bin/env bash
# Mask credential-bearing values from rendered manifests. `make
# install-dry-run` (and DRY_RUN=1) prints the full rendered manifests to the
# terminal and to collected CI logs, so two value classes are masked:
# Secret `data`/`stringData` payloads (values supplied through values
# overlays, including multi-line block scalars such as PEM keys), and the
# data of the endpoint-config ConfigMaps -- the AAP instance-group maps
# (`*-ig`, carrying EVPN/Netris controller URLs and any credential
# misplaced there instead of the parallel Secret) and the EVPN fabric
# config map (`osac-infra-evpn-config`, carrying internal node hostnames
# and fabric peer addresses). Resource structure, Secret/ConfigMap names
# and keys, and every other resource type stay readable so the dry run
# remains useful for review.
set -euo pipefail

# Helm renders each resource as a top-level document: kind and the data /
# stringData keys sit at column 0, payload entries one level deeper, block
# scalar bodies deeper still. The document separator resets state so a
# Secret cannot leak its scope into the next document, and any other
# column-0 key ends the payload block. The metadata `name:` rule only
# applies outside payloads, so a payload entry named `name` falls through
# to masking instead of printing its value.
awk '
/^---$/ { kind = ""; endpoint_configmap = 0; in_payload = 0; print; next }
/^kind: / { kind = $2; print; next }
!in_payload && /^  name: / {
    if (kind == "ConfigMap" \
        && ($2 ~ /-ig$/ || $2 == "osac-infra-evpn-config")) {
        endpoint_configmap = 1
    }
    print; next
}
kind == "Secret" && /^(data|stringData):$/ { in_payload = 1; print; next }
endpoint_configmap && /^data:$/ { in_payload = 1; print; next }
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
