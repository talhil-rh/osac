#!/usr/bin/env bash
# Render one `make install-dry-run` release without leaking Helm
# diagnostics. The rendered manifests go to stdout, masked by the
# Secret-payload redactor. Helm's diagnostics go to stderr, and Helm 3.22
# and later echo the rejected value in values-schema errors (an invalid
# customer-supplied evpn.vtepCIDR, for example), so a failed render prints
# only the value-free location that offline_render_error sanitizes. A
# successful render forwards its warnings through the redactor, so they
# stay readable without carrying a masked payload.
#
# Usage: render-dry-run.sh [HELM_TEMPLATE_ARGS...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"

err=$(mktemp)
trap 'rm -f "${err}"' EXIT

status=0
helm template "$@" 2>"${err}" | "${SCRIPT_DIR}/redact-secret-values.sh" \
    || status=$?
if (( status != 0 )); then
    offline_render_error "$(<"${err}")"
else
    "${SCRIPT_DIR}/redact-secret-values.sh" <"${err}" >&2
fi
exit "${status}"
