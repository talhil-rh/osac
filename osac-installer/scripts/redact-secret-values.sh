#!/usr/bin/env bash
# Mask credential-bearing values from rendered manifests. `make
# install-dry-run` (and DRY_RUN=1) prints the full rendered manifests to the
# terminal and to collected CI logs, so three value classes are masked:
# Secret `data`/`stringData` payloads (values supplied through values
# overlays, including multi-line block scalars such as PEM keys); the data
# of the endpoint-config ConfigMaps -- the AAP instance-group maps (`*-ig`,
# carrying EVPN/Netris controller URLs and any credential misplaced there
# instead of the parallel Secret), the EVPN fabric config map
# (`osac-infra-evpn-config`, carrying internal node hostnames and fabric
# peer addresses), and the MCE maps (`osac-infra-mce-image-overrides`,
# carrying registry hostnames in its manifest, and
# `osac-infra-mce-config`, carrying internal OS image mirror URLs in its
# osImages); container env entry values whose variable name is
# credential-shaped (PASSWORD/SECRET/TOKEN/ACCESS_KEY/AUTH/..., any
# *_KEY-suffixed name such as SIGNING_KEY or ENCRYPTION_KEY, and
# DSN/connection-string names, which often embed a password) or
# endpoint-shaped (URL/HOST/ADDR/..., plus Kafka broker lists such as
# KAFKA_BROKERS, whose metering value carries internal broker hosts),
# which callers can inject into
# workload specs as plain text instead of Secret references; and the
# registry host of image references that do not point at a well-known
# public registry, since image overrides carry internal registry
# hostnames; the resourceNames of RBAC rules that target Secrets --
# netbox.apiTokenSecret is customer-supplied and carries the same
# internal-identifier risk, so only Secret-scoped rules are masked and
# other resourceNames stay readable. The dnsNames and commonName of
# rendered Certificates, the host of Routes, and the hostnames of
# Gateway API routes and Gateways -- in full, including two-label
# service.namespace names and .svc/.cluster.local-suffixed names,
# because caller-supplied internal hostnames cannot be told apart from
# chart-internal ones by shape, and the keycloak route hostname and
# cluster domain land in the same fields. Block-scalar bodies of
# masked env values are dropped with their value line. Resource
# structure, Secret/ConfigMap names and keys, and every other value
# stay readable so the dry run remains useful for review.
set -euo pipefail

# Helm renders each resource as a top-level document: kind and the data /
# stringData keys sit at column 0, payload entries one level deeper, block
# scalar bodies deeper still. The document separator resets state so a
# Secret cannot leak its scope into the next document, and any other
# column-0 key ends the payload block. The metadata `name:` rule only
# applies outside payloads, so a payload entry named `name` falls through
# to masking instead of printing its value. An env entry's `value:` line
# always directly follows its `- name:` line in Helm's rendering, so the
# credential-name check only has to look one line ahead; a block-scalar
# value keeps its body on the following, deeper-indented lines, which are
# dropped until a line at or shallower than the value line's indent ends
# the block. RBAC rules list their target resources before resourceNames,
# so the Secret-scope check reads the sibling resources list.
awk '
# Masks every entry of a flow-style hostname list on the given line,
# keeping the key and the list shape intact.
function mask_flow_list(line,    head, body, n, i, out) {
    head = line
    sub(/\[.*/, "", head)
    body = line
    sub(/^[^\[]*\[/, "", body)
    sub(/\][[:space:]]*$/, "", body)
    n = split(body, host_arr, ",")
    out = "["
    for (i = 1; i <= n; i++) {
        if (i > 1) out = out ", "
        out = out "<redacted>"
    }
    return head out "]"
}
function flush_document(    index_line, metadata, name) {
    kind = ""; endpoint_configmap = 0; in_payload = 0; env_block = 0
    env_await_value = 0; role_secret_rule = 0; role_res_block = 0
    role_rn_block = 0; dns_block = 0
    for (index_line = 1; index_line <= document_length; index_line++) {
        $0 = document[index_line]
        if (/^kind: /) {
            kind = $2
            gsub(/["\047]/, "", kind)
        }
        if (/^[^ #]/) metadata = /^metadata:/
        if (metadata && /^  name: /) name = $2
    }
    gsub(/["\047]/, "", name)
    endpoint_configmap = kind == "ConfigMap" \
        && (name ~ /-ig$/ || name == "osac-infra-evpn-config" \
            || name == "osac-infra-mce-image-overrides" \
            || name == "osac-infra-mce-config")
    for (index_line = 1; index_line <= document_length; index_line++) {
        redact_line(document[index_line])
        delete document[index_line]
    }
    document_length = 0
}
function redact_line(line) {
    $0 = line
    if (/^kind: /) {
        kind = $2
        gsub(/["\047]/, "", kind)
        print; return
    }
    if (kind == "Secret" && /^(data|stringData):[[:space:]]*(#.*)?$/) { in_payload = 1; print; return }
    if (endpoint_configmap && /^data:[[:space:]]*(#.*)?$/) { in_payload = 1; print; return }
    if (/^[^ #]/) in_payload = 0
    # A masked block-scalar env value: its body lines are deeper-indented
    # than the value line itself and are dropped; a blank line inside the
    # block is dropped too. The first line at or shallower than the value
    # line indent ends the block and is processed normally.
    if (env_block) {
        match($0, /^ */)
        if ($0 ~ /^ *$/ || RLENGTH > env_block_indent) return
        env_block = 0
    }
    # Block-form RBAC lists carry their entries on the following lines, at
    # the same indent as their key in the Helm rendering; the list ends at
    # the first line at that indent that is not an entry. The resources
    # entries set the Secret scope and the resourceNames entries are
    # Secret names to mask.
    if (role_res_block) {
        match($0, /^ */)
        if (RLENGTH >= role_res_indent && $0 ~ /^ *- /) {
            role_res_item = $0
            sub(/^ *- /, "", role_res_item)
            if (role_res_item == "secrets") role_secret_rule = 1
        } else {
            role_res_block = 0
        }
    }
    if (role_rn_block) {
        match($0, /^ */)
        if (RLENGTH >= role_rn_indent && $0 ~ /^ *- /) {
            sub(/- .*/, "- <redacted>")
        } else {
            role_rn_block = 0
        }
    }
    # Block-form Certificate dnsNames and route/Gateway hostnames lists
    # carry their entries at the same indent as their key; the list ends
    # at the first line at that indent that is not an entry. Every entry
    # is masked in place.
    if (dns_block) {
        # Helm renders template comments inside these lists; they must not
        # end the block and carry nothing to mask.
        if ($0 ~ /^ *#/ || $0 ~ /^ *$/) { print; return }
        match($0, /^ */)
        if (RLENGTH >= dns_block_indent && $0 ~ /^ *- /) {
            sub(/- .*/, "- <redacted>")
        } else {
            dns_block = 0
        }
    }
    # Image references carry the registry hostname whenever callers override
    # images through values, and an internal registry hostname is endpoint
    # data. The registry host is the first path segment when it contains a
    # dot or colon (or is localhost); well-known public registries stay
    # readable so the common case remains reviewable.
    if ($0 ~ /^[[:space:]]*image: /) {
        match($0, /^[[:space:]]*image: */)
        img_head = substr($0, 1, RLENGTH)
        img_val = substr($0, RLENGTH + 1)
        img_quote = ""
        if (substr(img_val, 1, 1) == "\"") {
            img_quote = "\""
            img_val = substr(img_val, 2)
        }
        img_n = split(img_val, img_seg, "/")
        if (img_n > 1 && (img_seg[1] ~ /[.:]/ || img_seg[1] == "localhost") \
            && img_seg[1] !~ /^(quay\.io|docker\.io|ghcr\.io|gcr\.io|registry\.k8s\.io)$/) {
            sub(/^[^\/]*\//, "", img_val)
            $0 = img_head img_quote "<redacted>/" img_val
        }
    }
    if (env_await_value) {
        # Helm renders template comments inside env lists too, so a
        # comment (or blank) line between the name and value lines must
        # not end the one-line lookahead for the value line.
        if ($0 ~ /^ *#/ || $0 ~ /^ *$/) { print; return }
        env_await_value = 0
        if ($0 ~ /^[[:space:]]+value: ./ && (tolower(env_name) ~ \
            /(password|passwd|passphrase|secret|token|credential|api_key|private_key|access_key|auth|session|dsn|conn(ection)?_?str)/ \
            || tolower(env_name) ~ /(^|_)key$/ \
            || tolower(env_name) ~ /(url|host|endpoint|addr)/ \
            || tolower(env_name) == "kafka_brokers")) {
            if ($0 ~ /value: [|>]/) {
                match($0, /^ */)
                env_block_indent = RLENGTH
                env_block = 1
            }
            sub(/value: .*/, "value: <redacted>")
        }
    }
    if ($0 ~ /^[[:space:]]*- name: .+/) {
        env_name = $0
        sub(/^[[:space:]]*- name: */, "", env_name)
        # Helm quotes env names only when needed, but the redactor runs
        # over whole manifests, so a quoted name must match too: strip
        # the YAML double quotes before the exact KAFKA_BROKERS compare
        # (the regex checks are substring-based and quote-agnostic).
        gsub(/"/, "", env_name)
        env_await_value = 1
    }
    # RBAC rules that target Secrets name the Secret in resourceNames, and
    # a caller-set name (netbox.apiTokenSecret) carries the same
    # internal-identifier risk as the env values, so Secret-scoped rules
    # are masked; other resourceNames stay readable for RBAC review. Each
    # rules entry repeats its own resources list, which resets the scope.
    # Both list forms are covered: the flow list on the key line and the
    # block list whose entries follow at a deeper indent.
    if ((kind == "Role" || kind == "ClusterRole") \
        && $0 ~ /^[[:space:]]+resources:/) {
        role_secret_rule = 0
        if ($0 ~ /resources:$/) {
            match($0, /^ */)
            role_res_indent = RLENGTH
            role_res_block = 1
        } else {
            role_res = $0
            sub(/^[[:space:]]*resources: */, "", role_res)
            gsub(/[\[\]" ]/, "", role_res)
            role_n = split(role_res, role_arr, ",")
            for (role_i = 1; role_i <= role_n; role_i++) {
                if (role_arr[role_i] == "secrets") role_secret_rule = 1
            }
        }
    }
    if ((kind == "Role" || kind == "ClusterRole") && role_secret_rule \
        && $0 ~ /^[[:space:]]+resourceNames:/) {
        if ($0 ~ /resourceNames:$/) {
            match($0, /^ */)
            role_rn_indent = RLENGTH
            role_rn_block = 1
        } else {
            sub(/resourceNames: .*/, "resourceNames: [<redacted>]")
        }
    }
    # Certificate commonName and dnsNames entries, Route hosts, and the
    # hostnames of Gateway API routes and Gateways all carry hostnames,
    # and caller-supplied internal hostnames cannot be told apart from
    # chart-internal ones by shape, so every value in these fields is
    # masked. Both list forms are covered: the flow list on the key line
    # and the block list whose entries follow at the same indent.
    if (kind == "Certificate" && $0 ~ /^[[:space:]]+commonName: /) {
        sub(/commonName: .*/, "commonName: <redacted>")
    }
    if (kind == "Certificate" && $0 ~ /^[[:space:]]+dnsNames: \[/) {
        $0 = mask_flow_list($0)
    }
    if (kind == "Certificate" && $0 ~ /^[[:space:]]+dnsNames:$/) {
        match($0, /^ */)
        dns_block_indent = RLENGTH
        dns_block = 1
    }
    if ((kind ~ /Route$/ || kind == "Gateway") \
        && $0 ~ /^[[:space:]]+hostnames: \[/) {
        $0 = mask_flow_list($0)
    }
    if ((kind ~ /Route$/ || kind == "Gateway") \
        && $0 ~ /^[[:space:]]+hostnames:$/) {
        match($0, /^ */)
        dns_block_indent = RLENGTH
        dns_block = 1
    }
    if (kind == "Route" && $0 ~ /^[[:space:]]+host: /) {
        sub(/host: .*/, "host: <redacted>")
    }
    if (in_payload) {
        # Block-scalar body lines (indent deeper than the entry keys) are
        # dropped outright; single-line entry values are masked in place.
        if ($0 ~ /^   +[^ ]/) return
        if ($0 ~ /^  [^ :][^:]*: ./) sub(/: .*/, ": <redacted>")
    }
    print
}
/^---([[:space:]]+#.*)?[[:space:]]*$/ { separator = $0; flush_document(); print separator; next }
{ document[++document_length] = $0 }
END { flush_document() }
'
