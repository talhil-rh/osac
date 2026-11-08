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
# credential-shaped (PASSWORD/SECRET/TOKEN/ACCESS_KEY/AUTH/...) or
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
# rendered Certificates and the host of Routes, when they are not
# cluster-internal names (bare service names, localhost, or
# .svc/.cluster.local-suffixed), since the keycloak route hostname and
# the cluster domain are customer-supplied. Block-scalar bodies of
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
# A hostname in a Certificate or Route field stays readable when it is
# cluster-internal: a bare service name, a service.namespace pair, a
# name suffixed with .svc or .cluster.local, or localhost, with an
# optional wildcard. Anything else carries a caller-supplied domain and
# is masked.
function host_is_readable(h) {
    sub(/^\*\./, "", h)
    if (h == "localhost") return 1
    if (index(h, ".") == 0) return 1
    if (h ~ /\.svc(\.cluster\.local)?$/ || h ~ /\.cluster\.local$/) return 1
    if (split(h, host_lbl, ".") == 2) return 1
    return 0
}
# Masks the non-readable entries of a flow-style hostname list on the
# given line, keeping the key and the readable entries intact.
function mask_flow_list(line,    head, body, n, i, item, out) {
    head = line
    sub(/\[.*/, "", head)
    body = line
    sub(/^[^\[]*\[/, "", body)
    sub(/\][[:space:]]*$/, "", body)
    n = split(body, host_arr, ",")
    out = "["
    for (i = 1; i <= n; i++) {
        item = host_arr[i]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", item)
        gsub(/"/, "", item)
        if (i > 1) out = out ", "
        if (host_is_readable(item)) out = out item
        else out = out "<redacted>"
    }
    return head out "]"
}
/^---$/ { kind = ""; endpoint_configmap = 0; in_payload = 0; env_block = 0; role_secret_rule = 0; role_res_block = 0; role_rn_block = 0; dns_block = 0; print; next }
/^kind: / { kind = $2; print; next }
!in_payload && /^  name: / {
    if (kind == "ConfigMap" \
        && ($2 ~ /-ig$/ || $2 == "osac-infra-evpn-config" \
            || $2 == "osac-infra-mce-image-overrides" \
            || $2 == "osac-infra-mce-config")) {
        endpoint_configmap = 1
    }
    print; next
}
kind == "Secret" && /^(data|stringData):$/ { in_payload = 1; print; next }
endpoint_configmap && /^data:$/ { in_payload = 1; print; next }
/^[^ ]/ { in_payload = 0 }
{
    # A masked block-scalar env value: its body lines are deeper-indented
    # than the value line itself and are dropped; a blank line inside the
    # block is dropped too. The first line at or shallower than the value
    # line indent ends the block and is processed normally.
    if (env_block) {
        match($0, /^ */)
        if ($0 ~ /^ *$/ || RLENGTH > env_block_indent) next
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
    # Block-form Certificate dnsNames and HTTPRoute/Gateway hostnames
    # lists carry their entries at the same indent as their key; the list
    # ends at the first line at that indent that is not an entry. Entries
    # that are not cluster-internal names are masked in place.
    if (dns_block) {
        # Helm renders template comments inside these lists; they must not
        # end the block and carry nothing to mask.
        if ($0 ~ /^ *#/ || $0 ~ /^ *$/) { print; next }
        match($0, /^ */)
        if (RLENGTH >= dns_block_indent && $0 ~ /^ *- /) {
            dns_entry = $0
            sub(/^ *- /, "", dns_entry)
            gsub(/"/, "", dns_entry)
            if (!host_is_readable(dns_entry)) sub(/- .*/, "- <redacted>")
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
        env_await_value = 0
        if ($0 ~ /^[[:space:]]+value: ./ && (tolower(env_name) ~ \
            /(password|passwd|passphrase|secret|token|credential|api_key|private_key|access_key|auth|session)/ \
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
    # hostnames of Gateway API routes and Gateways carry the
    # caller-supplied keycloak route hostname and cluster domain; the
    # fixed service names stay readable so the SAN sets and routes remain
    # reviewable. Both list forms are covered: the flow list on the key
    # line and the block list whose entries follow at the same indent.
    if (kind == "Certificate" && $0 ~ /^[[:space:]]+commonName: /) {
        cn_val = $0
        sub(/^[[:space:]]*commonName: */, "", cn_val)
        gsub(/"/, "", cn_val)
        if (!host_is_readable(cn_val)) sub(/commonName: .*/, "commonName: <redacted>")
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
        route_host = $0
        sub(/^[[:space:]]*host: */, "", route_host)
        gsub(/"/, "", route_host)
        if (!host_is_readable(route_host)) sub(/host: .*/, "host: <redacted>")
    }
    if (in_payload) {
        # Block-scalar body lines (indent deeper than the entry keys) are
        # dropped outright; single-line entry values are masked in place.
        if ($0 ~ /^   +[^ ]/) next
        if ($0 ~ /^  [^ :][^:]*: ./) sub(/: .*/, ": <redacted>")
    }
    print
}
'
