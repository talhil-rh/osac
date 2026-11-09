#!/usr/bin/env bash
# Mask credential-bearing values from rendered manifests. `make
# install-dry-run` (and DRY_RUN=1) prints the full rendered manifests to the
# terminal and to collected CI logs, so these value classes are masked:
# Secret `data`/`stringData` payloads (values supplied through values
# overlays, including multi-line block scalars such as PEM keys); the data
# of the endpoint-config ConfigMaps -- the AAP instance-group maps (`*-ig`,
# carrying EVPN/Netris controller URLs and any credential misplaced there
# instead of the parallel Secret), the EVPN fabric config map
# (`osac-infra-evpn-config`, carrying internal node hostnames and fabric
# peer addresses), and the MCE maps (`osac-infra-mce-image-overrides`,
# carrying registry hostnames in its manifest, and
# `osac-infra-mce-config`, carrying internal OS image mirror URLs in its
# osImages); ConfigMap data entries whose key is endpoint-shaped
# (URL/HOST/ADDR/ENDPOINT, such as the UI chart's FULFILLMENT_API_URL and
# OIDC_ISSUER_URL), since a caller override can point them at an internal
# host; container env entry values whose variable name is
# credential-shaped (PASSWORD/SECRET/TOKEN/ACCESS_KEY/AUTH/..., any
# *_KEY-suffixed name such as SIGNING_KEY or ENCRYPTION_KEY, and
# DSN/connection-string names, which often embed a password),
# endpoint-shaped (URL/HOST/ADDR/..., Kafka broker lists such as
# KAFKA_BROKERS, whose metering value carries internal broker hosts),
# service-name-shaped (such as INTERNAL_SVC, whose caller-overridden value
# is an internal service name), tenant-shaped (TENANT, whose value is the
# caller-supplied tenant name), user-shaped (TENANT_USERS, whose value is
# a caller-supplied tenant user list that can carry email addresses), or
# image-shaped (OSAC_EE_IMAGE, whose caller-overridden value can point at
# an internal registry), which callers can inject into workload specs as
# plain text instead of Secret references; and the registry host of image
# references that do not point at a well-known public registry, since
# image overrides carry internal registry hostnames; the resourceNames
# of RBAC rules that target Secrets -- netbox.apiTokenSecret is
# customer-supplied and carries the
# same internal-identifier risk, so only Secret-scoped rules are masked,
# other resourceNames stay readable, and each rule's scope is resolved
# from its resources regardless of key order. The dnsNames and commonName
# of rendered Certificates, the host of Routes, the hostnames of Gateway
# API routes, and the hostname of each Gateway listener -- in full,
# including two-label service.namespace names and
# .svc/.cluster.local-suffixed names, because caller-supplied internal
# hostnames cannot be told apart from chart-internal ones by shape, and
# the keycloak route hostname and cluster domain land in the same fields.
# Block-scalar bodies of masked env values and masked ConfigMap values
# are dropped with their value line. Resource structure,
# Secret/ConfigMap names and keys, and every other value stay readable so
# the dry run remains useful for review.
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
# the block. An RBAC rule may list its keys in any order, so each
# document's resourceNames lines are scoped to their rule's resources
# before the line pass runs.
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
# Indent of the key text on a line, counting a list-item dash as
# structure so `- resources:` and `  resources:` compare as siblings.
function key_indent(line,    indent) {
    match(line, /^ */)
    indent = RLENGTH
    if (substr(line, indent + 1, 2) == "- ") indent += 2
    return indent
}
# True when the rule whose resources key is at key_index targets Secrets:
# flow-list entries parse from the key line, block-list entries follow at
# the key indent or deeper and end at the next rule item (a mapping
# key) or any non-item line.
function rule_targets_secrets(key_index, rule_end,    line, k, item, items, n, parts) {
    line = document[key_index]
    if (line ~ /resources:[[:space:]]*$/) {
        for (k = key_index + 1; k <= rule_end; k++) {
            if (document[k] ~ /^[[:space:]]*#/ || document[k] ~ /^[[:space:]]*$/) continue
            if (document[k] !~ /^[[:space:]]*- /) break
            match(document[k], /^ */)
            if (RLENGTH < key_indent(line)) break
            item = document[k]
            sub(/^[[:space:]]*- */, "", item)
            sub(/[[:space:]]*#.*$/, "", item)
            gsub(/["\047]/, "", item)
            if (item ~ /:/) break
            if (tolower(item) == "secrets") return 1
        }
        return 0
    }
    items = line
    sub(/^[[:space:]]*(- )?resources: */, "", items)
    gsub(/[\[\]"\047 ]/, "", items)
    n = split(items, parts, ",")
    for (k = 1; k <= n; k++) {
        if (parts[k] == "secrets") return 1
    }
    return 0
}
# Marks every resourceNames line that belongs to a Secret-targeting rule.
# The keys of a rule can come in any order (a Role supplied through
# netbox.extraDeploy is arbitrary YAML), so each resourceNames line is
# paired with resources in the same rule, never with a neighbouring rule:
# a rule starts at each rules list item (a dash line whose item opens a
# mapping) and ends at the next item or at a shallower line.
function mark_role_secret_names(    i, j, rule_end, rule_indent, key_ind, res_secret) {
    for (i = 1; i <= document_length; i++) rn_secret[i] = 0
    for (i = 1; i <= document_length; i++) {
        if (document[i] !~ /^[[:space:]]*- [^ ].*:/) continue
        match(document[i], /^ */)
        rule_indent = RLENGTH
        key_ind = key_indent(document[i])
        rule_end = document_length
        for (j = i + 1; j <= document_length; j++) {
            if (document[j] ~ /^[[:space:]]*$/ || document[j] ~ /^[[:space:]]*#/) continue
            match(document[j], /^ */)
            if (RLENGTH < rule_indent) { rule_end = j - 1; break }
            if (RLENGTH == rule_indent \
                && document[j] ~ /^[[:space:]]*- [^ ].*:/) { rule_end = j - 1; break }
        }
        res_secret = 0
        for (j = i; j <= rule_end; j++) {
            if (document[j] ~ /^[[:space:]]*(- )?resources:/ \
                && key_indent(document[j]) == key_ind) {
                if (rule_targets_secrets(j, rule_end)) res_secret = 1
            }
        }
        if (!res_secret) continue
        for (j = i; j <= rule_end; j++) {
            if (document[j] ~ /^[[:space:]]*(- )?resourceNames:/ \
                && key_indent(document[j]) == key_ind) rn_secret[j] = 1
        }
    }
}
function flush_document(    index_line, metadata, name) {
    kind = ""; endpoint_configmap = 0; in_payload = 0; env_block = 0
    config_block = 0; env_await_value = 0; role_rn_block = 0; dns_block = 0
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
    if (kind == "Role" || kind == "ClusterRole") mark_role_secret_names()
    for (index_line = 1; index_line <= document_length; index_line++) {
        redact_line(document[index_line], index_line)
        delete document[index_line]
    }
    document_length = 0
}
function redact_line(line, line_no) {
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
    # A masked ConfigMap value may be a block scalar too; its body lines
    # are deeper-indented than the key and are dropped, like env blocks.
    if (config_block) {
        match($0, /^ */)
        if ($0 ~ /^ *$/ || RLENGTH > config_block_indent) return
        config_block = 0
    }
    # Block-form resourceNames lists carry their entries on the following
    # lines, at the same indent as their key in the Helm rendering; the
    # list ends at the first line at that indent that is not an entry. The
    # document pre-scan marks only the lists of Secret-targeting rules.
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
    # readable so the common case remains reviewable. Container entries are
    # rendered either as `image:` keys or as `- image:` list items, and a
    # quoted value keeps its quote in the output so the YAML stays valid.
    if ($0 ~ /^[[:space:]]*(- )?image: /) {
        match($0, /^[[:space:]]*(- )?image: */)
        img_head = substr($0, 1, RLENGTH)
        img_val = substr($0, RLENGTH + 1)
        img_quote = ""
        if (substr(img_val, 1, 1) == "\"" || substr(img_val, 1, 1) == "\047") {
            img_quote = substr(img_val, 1, 1)
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
            || tolower(env_name) ~ /(^|_)(svc|service)(_|$)/ \
            || tolower(env_name) ~ /(^|_)(tenant|tenants)(_|$)/ \
            || tolower(env_name) ~ /(^|_)(user|users|email|emails)(_|$)/ \
            || tolower(env_name) ~ /(^|_)image$/ \
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
        # the YAML quotes (either style) before the exact KAFKA_BROKERS
        # compare (the regex checks are substring-based and quote-agnostic).
        gsub(/["\047]/, "", env_name)
        env_await_value = 1
    }
    # RBAC rules that target Secrets name the Secret in resourceNames, and
    # a caller-set name (netbox.apiTokenSecret) carries the same
    # internal-identifier risk as the env values, so Secret-scoped rules
    # are masked; other resourceNames stay readable for RBAC review. The
    # document pre-scan resolved the resources of each rule regardless of
    # key order and marked the lists to mask; both list forms are covered,
    # the flow list on the key line and the block list whose entries
    # follow.
    if ((kind == "Role" || kind == "ClusterRole") && rn_secret[line_no] \
        && $0 ~ /^[[:space:]]*(- )?resourceNames:/) {
        if ($0 ~ /resourceNames:$/) {
            match($0, /^ */)
            role_rn_indent = RLENGTH
            role_rn_block = 1
        } else {
            sub(/resourceNames: .*/, "resourceNames: [<redacted>]")
        }
    }
    # Certificate commonName and dnsNames entries, Route hosts, the
    # hostname lists of Gateway API routes, and each Gateway listener
    # hostname all carry hostnames, and caller-supplied internal hostnames
    # cannot be told apart from chart-internal ones by shape, so every
    # value in these fields is masked. Route hostname lists are covered in
    # both forms: the flow list on the key line and the block list whose
    # entries follow at the same indent.
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
    if (kind ~ /Route$/ && $0 ~ /^[[:space:]]+hostnames: \[/) {
        $0 = mask_flow_list($0)
    }
    if (kind ~ /Route$/ && $0 ~ /^[[:space:]]+hostnames:$/) {
        match($0, /^ */)
        dns_block_indent = RLENGTH
        dns_block = 1
    }
    if (kind == "Route" && $0 ~ /^[[:space:]]+host: /) {
        sub(/host: .*/, "host: <redacted>")
    }
    # A Gateway carries its host in the singular hostname field of each
    # listener, never in a hostnames list.
    if (kind == "Gateway" && $0 ~ /^[[:space:]]*(- )?hostname: /) {
        sub(/hostname: .*/, "hostname: <redacted>")
    }
    # ConfigMap data entries whose key is endpoint-shaped carry a
    # caller-overridable internal hostname (the FULFILLMENT_API_URL of
    # the UI chart and OIDC_ISSUER_URL are plain data entries, not
    # env entries), so they are masked in every ConfigMap; other data
    # entries stay readable.
    if (kind == "ConfigMap" && $0 ~ /^  [^ :][^:]*: ./) {
        config_key = $0
        sub(/:.*/, "", config_key)
        if (tolower(config_key) ~ /(url|host|addr|endpoint)/) {
            if ($0 ~ /: [|>]/) {
                match($0, /^ */)
                config_block_indent = RLENGTH
                config_block = 1
            }
            sub(/: .*/, ": <redacted>")
        }
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
