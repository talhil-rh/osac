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
# host, or credential-shaped (PASSWORD/SECRET/TOKEN/... and
# *_KEY-suffixed names, such as a ConfigMap a values overlay renders
# through the NetBox chart's extraDeploy), in every ConfigMap; container
# env entry values whose variable name is
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
# are dropped with their value line; a block-scalar ConfigMap value under
# any other key is a configuration-file payload, and a credential
# assignment inside it (`password: x`, `token = x`, `"client_secret": x`,
# also behind an `export ` or `- ` prefix or later in the line) is masked
# in place so the rest of the file stays readable; a URL host, an
# internal-shaped hostname (`.svc`, `.internal`, `.local` labels), and a
# credential in a URL query parameter are masked in place for the same
# reason. The same payload collapsed onto one line
# (`app.conf: host=db password=x`) is masked as a whole, because that
# line has no other content to keep. Resource
# structure, Secret/ConfigMap names and keys, and every other value stay
# readable so the dry run remains useful for review.
set -euo pipefail

# Helm renders each resource as a top-level document: kind and the data /
# stringData keys sit at column 0, payload entries one level deeper, block
# scalar bodies deeper still. The document separator resets state so a
# Secret cannot leak its scope into the next document, and any other
# column-0 key ends the payload block. The metadata `name:` rule only
# applies outside payloads, so a payload entry named `name` falls through
# to masking instead of printing its value. Helm renders an env item's
# `name:` before its `value:`, but a values overlay can add arbitrary
# YAML (netbox.extraDeploy), so each document's env items are pre-scanned
# and the value line is masked whatever the key order, including a
# flow-style item whose name and value share the line; a block-scalar
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
# Scans a flow collection for its matching close, starting from the given
# open depth. Braces inside quoted scalars do not count. Returns the index
# of the closing brace on this line, or 0 when the line ends first; the
# depth still open is left in flow_depth.
function flow_close(line, depth,    i, c, quote) {
    quote = ""
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (quote != "") {
            if (c == quote) quote = ""
            continue
        }
        if (c == "\"" || c == "\047") { quote = c; continue }
        if (c == "{") {
            depth++
        } else if (c == "}") {
            depth--
            if (depth == 0) { flow_depth = 0; return i }
        }
    }
    flow_depth = depth
    return 0
}
# Advances a flow-map scan over one line of a multi-line item, carrying the
# brace depth in flow_depth and the quote state in flow_quote from the
# previous line. A quoted scalar can wrap onto the following lines and its
# closing quote must not be read as a new opening quote, so the quote state
# is kept across lines. Returns the column of the brace that closes the
# item, or 0 when the item continues on the next line.
function flow_scan(line, depth,    i, c) {
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (flow_quote == "\"") {
            # An escaped double quote does not end the scalar.
            if (c == "\\") { i++; continue }
            if (c == "\"") flow_quote = ""
            continue
        }
        if (flow_quote == "\047") {
            # A doubled single quote stands for one quote character and does
            # not end the scalar.
            if (c == "\047") {
                if (substr(line, i + 1, 1) == "\047") { i++; continue }
                flow_quote = ""
            }
            continue
        }
        if (c == "\"" || c == "\047") { flow_quote = c; continue }
        if (c == "{") {
            depth++
        } else if (c == "}") {
            depth--
            if (depth == 0) { flow_depth = 0; flow_quote = ""; return i }
        }
    }
    flow_depth = depth
    return 0
}
# True when a data key or env variable name is credential-shaped: the
# secret-bearing words, any KEY-suffixed name (SIGNING_KEY, ENCRYPTION_KEY,
# signing-key, and the camelCase signingKey this chart family also uses),
# and DSN/connection-string names, which often embed a password.
function credential_name(name,    lower) {
    lower = tolower(name)
    return lower ~ /(password|passwd|passphrase|secret|token|credential|api_key|private_key|access_key|auth|session|dsn|conn(ection)?_?str)/ \
        || lower ~ /(^|[_-])key$/ \
        || name ~ /[a-z0-9]Key$/
}
# True when an env variable name marks its value as confidential or as
# carrying endpoint/identity data the dry run must not print.
function sensitive_env_name(name,    lower) {
    lower = tolower(name)
    return credential_name(name) \
        || lower ~ /(url|host|endpoint|addr)/ \
        || lower ~ /(^|_)(svc|service)(_|$)/ \
        || lower ~ /(^|_)(tenant|tenants)(_|$)/ \
        || lower ~ /(^|_)(user|users|email|emails)(_|$)/ \
        || lower ~ /(^|_)image$/ \
        || lower == "kafka_brokers"
}
# True when a key inside a configuration-file payload is credential-shaped.
# Tighter than credential_name(): file content is prose-like, so the
# ambiguous words auth/session must be a delimited component (an `author`
# or `oauth` line is not a credential), while the unambiguous words match
# anywhere (client_secret, DB_PASSWORD, Authorization headers). A delimited
# KEY suffix and a camelCase Key suffix are credentials too
# (encryption_key, SIGNING_KEY, signingKey); a bare `key` stays readable
# because `- key: value` is common in selectors, and dotted names like
# tls.key stay readable because they usually hold file paths.
function credential_file_key(name,    lower) {
    lower = tolower(name)
    return lower ~ /(password|passwd|passphrase|secret|token|credential|authorization|api[_.-]?key|private[_.-]?key|access[_.-]?key|dsn)/ \
        || lower ~ /(^|[_.-])(auth|session)([_.-]|$)/ \
        || lower ~ /[_-]key$/ \
        || name ~ /[a-z0-9]Key$/
}
# True when a key inside a configuration-file payload carries a header
# credential. Its value is an authentication scheme followed by the
# credential (`Authorization: Bearer x`, `auth: Basic x`), so the whole
# value is masked; masking only the first word would print the token.
function header_credential_key(name,    lower) {
    lower = tolower(name)
    return lower ~ /authorization/ \
        || lower ~ /(^|[_.-])auth([_.-]|$)/
}
# Masks credential values in an inline JSON object on one line, keeping
# the key and the rest of the line readable. Only quoted string values
# are considered, and a line without such fields passes through.
function mask_json_credentials(line,    out, rest, obj, key, val) {
    out = ""
    rest = line
    # JSON string values may contain escaped quotes and backslashes, so the
    # value pattern consumes an escape pair before it can end the string;
    # otherwise a `\"` inside a credential would cut the match short and
    # print the rest of the value. A backslash is never an ordinary
    # character, so a trailing `\\` cannot pair with the closing quote and
    # swallow the opening quote of the next field.
    while (match(rest, /"[A-Za-z0-9_.-]+"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"/)) {
        obj = substr(rest, RSTART, RLENGTH)
        key = obj
        sub(/^"/, "", key)
        sub(/".*/, "", key)
        out = out substr(rest, 1, RSTART - 1)
        if (credential_file_key(key)) {
            val = obj
            sub(/^[^:]*:[[:space:]]*/, "", val)
            out = out substr(obj, 1, length(obj) - length(val)) "\"<redacted>\""
        } else {
            out = out obj
        }
        rest = substr(rest, RSTART + RLENGTH)
    }
    return out rest
}
# True when a single-line configuration-file value carries a credential
# assignment anywhere in it: file content collapsed onto its key line
# (`host=db password=x`), an inline JSON object (`{"token":"x"}`), or a
# URL query (`?token=x`). Detection only; the caller masks the whole
# value because a one-line payload has no other line to keep readable.
function has_inline_credential(text,    rest, found, key) {
    rest = text
    while (match(rest, /(^|[[:space:];,&?{])["\047]?[A-Za-z0-9_.-]+["\047]?[[:space:]]*[:=]/)) {
        found = substr(rest, RSTART, RLENGTH)
        key = found
        sub(/^[^A-Za-z0-9_.-]*/, "", key)
        sub(/["\047]?[[:space:]]*[:=]$/, "", key)
        if (credential_file_key(key)) return 1
        rest = substr(rest, RSTART + RLENGTH)
    }
    return 0
}
# Credential-bearing URL query parameters (`?token=x`, `&api_key=y`) are
# masked in place, keeping the parameter name and the rest of the line
# readable. A URL can sit in a neutral setting such as
# `endpoint = https://host/api`, so the query key decides, not the line
# key. The value is masked through the next separator or whitespace,
# which also takes any surrounding quotes with it.
function mask_query_credentials(text,    out, rest, found, key) {
    out = ""
    rest = text
    while (match(rest, /[?&]["\047]?[A-Za-z0-9_.-]+["\047]?=/)) {
        found = substr(rest, RSTART, RLENGTH)
        key = found
        sub(/^[?&]/, "", key)
        sub(/["\047]?=$/, "", key)
        out = out substr(rest, 1, RSTART + RLENGTH - 1)
        rest = substr(rest, RSTART + RLENGTH)
        if (credential_file_key(key) && match(rest, /^[^&[:space:]]*/)) {
            if (header_credential_key(key)) {
                # A header credential carries a scheme and the token, so
                # the value runs through the next parameter, not only to
                # the next space.
                match(rest, /^[^&]*/)
            }
            rest = "<redacted>" substr(rest, RLENGTH + 1)
        }
    }
    return out rest
}
# Length of a scalar at the start of text: a double-quoted scalar through
# its closing quote (a backslash escapes the next character), a
# single-quoted scalar through its closing quote (a doubled quote is one
# character), or a plain scalar matching the given regular expression.
function scalar_length(text, plain,    i, c, quote) {
    quote = substr(text, 1, 1)
    if (quote == "\"") {
        for (i = 2; i <= length(text); i++) {
            c = substr(text, i, 1)
            if (c == "\\") {
                i++
            } else if (c == "\"") {
                return i
            }
        }
        return length(text)
    }
    if (quote == "\047") {
        for (i = 2; i <= length(text); i++) {
            if (substr(text, i, 1) != "\047") continue
            if (substr(text, i + 1, 1) == "\047") {
                i++
            } else {
                return i
            }
        }
        return length(text)
    }
    if (match(text, plain)) return RLENGTH
    return 0
}
# Index of the quote that closes a quoted scalar whose opening quote was
# on an earlier line, or 0 when the scalar continues below. A backslash
# escapes the next character in a double-quoted scalar, and a doubled
# single quote stands for one quote character, so neither ends the scalar.
function closing_quote(text, quote,    i, c) {
    for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (quote == "\"") {
            if (c == "\\") {
                i++
            } else if (c == "\"") {
                return i
            }
        } else {
            if (c != "\047") continue
            if (substr(text, i + 1, 1) == "\047") {
                i++
            } else {
                return i
            }
        }
    }
    return 0
}
# Masks internal-shaped hostnames (`.svc`, `.internal` and `.local`
# suffixes, including `.svc.cluster.local`) wherever they appear on a
# configuration-file line, keeping the port and the rest of the line.
function mask_internal_hostnames(text,    out, rest) {
    out = ""
    rest = text
    while (match(rest, /[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.(svc|internal|local)(\.[A-Za-z0-9-]+)*([.:][0-9]+)?/)) {
        if (RSTART > 1 && substr(rest, RSTART - 1, 1) ~ /[A-Za-z0-9.-]/) {
            out = out substr(rest, 1, RSTART)
            rest = substr(rest, RSTART + 1)
            continue
        }
        out = out substr(rest, 1, RSTART - 1) "<redacted>"
        rest = substr(rest, RSTART + RLENGTH)
    }
    return out rest
}
# The host of a URL is endpoint data in a configuration-file payload, so
# it is masked in full; the scheme, any userinfo and any path stay
# readable, and a closing quote or bracket after a host without a path is
# left in place.
function mask_url_hosts(text,    out, rest) {
    out = ""
    rest = text
    while (match(rest, /:\/\//)) {
        out = out substr(rest, 1, RSTART + RLENGTH - 1)
        rest = substr(rest, RSTART + RLENGTH)
        # Userinfo is masked by the caller before this runs; if it is still
        # there, keep it and mask the host after it, so a URL cannot keep
        # its host past an `@`. An `@` past the end of the authority is
        # query data, not userinfo.
        if (match(rest, /^[^\/[:space:]"\047?#]*@/)) {
            out = out substr(rest, 1, RLENGTH)
            rest = substr(rest, RLENGTH + 1)
        }
        # The host ends at the path, a query or fragment, whitespace, a
        # quote, an `@`, or an already-masked placeholder.
        if (match(rest, /^[^\/[:space:]@"\047?#<]+/))
            rest = "<redacted>" substr(rest, RLENGTH + 1)
    }
    return out rest
}
# Credential assignments embedded anywhere in a configuration-file line
# (`options = user=x password=y`) are masked in place, keeping the key
# and the rest of the line readable. A quoted value is masked through its
# closing quote, so a separator inside it cannot expose the suffix.
function mask_embedded_credentials(text,    out, rest, found, key, n, quote) {
    out = ""
    rest = text
    while (match(rest, /(^|[[:space:];,&?{])["\047]?[A-Za-z0-9_.-]+["\047]?[[:space:]]*[:=][[:space:]]*/)) {
        found = substr(rest, RSTART, RLENGTH)
        key = found
        sub(/^[^A-Za-z0-9_.-]*/, "", key)
        sub(/["\047]?[[:space:]]*[:=][[:space:]]*$/, "", key)
        out = out substr(rest, 1, RSTART + RLENGTH - 1)
        rest = substr(rest, RSTART + RLENGTH)
        if (credential_file_key(key)) {
            if (header_credential_key(key)) {
                # A header credential is a scheme and the token after it
                # (`Bearer x`), so the whole value is masked through its
                # closing quote, the next field separator, or the end of
                # the line. Masking only the first word would print the
                # token, as the scheme is always followed by one.
                quote = substr(rest, 1, 1)
                if (quote == "\"" || quote == "\047") {
                    n = scalar_length(rest, "")
                    rest = quote "<redacted>" quote substr(rest, n + 1)
                } else if (match(rest, /^([^"\047;&},]|\\.)*/)) {
                    rest = "<redacted>" substr(rest, RLENGTH + 1)
                }
            } else {
                n = scalar_length(rest, "^[^[:space:];,&}]*")
                quote = substr(rest, 1, 1)
                if (quote == "\"" || quote == "\047") {
                    # Keep the quotes so an inline JSON object keeps its
                    # shape; only the content between them is masked.
                    rest = quote "<redacted>" quote substr(rest, n + 1)
                } else {
                    rest = "<redacted>" substr(rest, n + 1)
                }
            }
        }
    }
    return out rest
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
# Marks value lines of env list items whose sibling name is sensitive,
# whatever the key order inside the item. Helm renders name before value,
# but a values overlay can introduce arbitrary YAML (netbox.extraDeploy),
# so the one-line lookahead in redact_line alone would miss a value written
# before its name. Flow-style items (`- {name: X, value: Y}`) are marked
# whole and masked in place, because name and value share the item line;
# an item can wrap onto the following lines, so the item is joined before
# the name is read and every line it spans is marked. The join runs to the
# closing brace with no line limit, and an item that never closes is masked
# to the end of the document, because YAML reads the remainder as its value.
function mark_env_secret_values(    i, j, end, ind, key_ind, name, sensitive, text, closed) {
    for (i = 1; i <= document_length; i++) {
        env_secret[i] = 0
        env_flow[i] = 0
    }
    for (i = 1; i <= document_length; i++) {
        if (document[i] !~ /^[[:space:]]*- [^ ].*:/) continue
        if (document[i] ~ /^[[:space:]]*- \{/) {
            # A flow item can wrap onto the following lines, putting the
            # name on one line and the value on another, so the item is
            # joined before the name is read. Every line of a sensitive
            # item is marked, because the value can sit on any of them.
            text = document[i]
            end = i
            closed = 0
            flow_quote = ""
            if (flow_scan(document[i], 0) != 0) {
                closed = 1
            } else {
                # Join through the brace that closes the item. There is no
                # line cap: a name or value beyond a fixed limit would
                # print, so the document end is the only limit.
                for (j = i + 1; j <= document_length; j++) {
                    text = text " " document[j]
                    end = j
                    if (flow_scan(document[j], flow_depth) != 0) {
                        closed = 1
                        break
                    }
                }
            }
            if (!closed) {
                # An item that never closes extends to the end of the
                # document under YAML flow rules, so the remainder is
                # treated as its value.
                for (j = i; j <= document_length; j++) {
                    env_secret[j] = 1
                    env_flow[j] = 1
                }
                continue
            }
            if (!match(text, /(^|[{,[:space:]])name:[[:space:]]*("[^"]*"|\047[^\047]*\047|[^,}]*)/)) continue
            name = substr(text, RSTART, RLENGTH)
            sub(/^.*name:[[:space:]]*/, "", name)
            gsub(/["\047]/, "", name)
            sub(/^[[:space:]]+/, "", name)
            sub(/[[:space:]]+$/, "", name)
            if (!sensitive_env_name(name)) continue
            for (j = i; j <= end; j++) {
                env_secret[j] = 1
                env_flow[j] = 1
            }
            continue
        }
        match(document[i], /^ */)
        ind = RLENGTH
        key_ind = key_indent(document[i])
        end = document_length
        for (j = i + 1; j <= document_length; j++) {
            if (document[j] ~ /^[[:space:]]*$/ || document[j] ~ /^[[:space:]]*#/) continue
            match(document[j], /^ */)
            if (RLENGTH < ind) { end = j - 1; break }
            if (RLENGTH == ind && document[j] ~ /^[[:space:]]*- [^ ].*:/) { end = j - 1; break }
        }
        sensitive = 0
        for (j = i; j <= end; j++) {
            if (key_indent(document[j]) != key_ind) continue
            if (document[j] ~ /^[[:space:]]*(- )?name: /) {
                name = document[j]
                sub(/^[[:space:]]*(- )?name: */, "", name)
                gsub(/["\047]/, "", name)
                sensitive = sensitive_env_name(name)
            }
        }
        if (!sensitive) continue
        for (j = i; j <= end; j++) {
            if (key_indent(document[j]) != key_ind) continue
            if (document[j] ~ /^[[:space:]]*(- )?value:([[:space:]]|$)/) env_secret[j] = 1
        }
    }
}
function flush_document(    index_line, metadata, name) {
    kind = ""; endpoint_configmap = 0; in_payload = 0; env_block = 0
    env_flow_cont = 0; env_flow_quote = ""
    config_block = 0; config_file_block = 0
    file_nested = 0; file_nested_indent = 0
    role_rn_block = 0; dns_block = 0
    configmap_document = 0; configmap_data = 0; configmap_binary = 0
    payload_flow = 0; payload_flow_depth = 0
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
    configmap_document = kind == "ConfigMap"
    if (kind == "Role" || kind == "ClusterRole") mark_role_secret_names()
    mark_env_secret_values()
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
    # Continuation lines of a flow-style Secret data/stringData map are
    # dropped with it; see the flow-map rule below.
    if (payload_flow) {
        if (flow_close($0, payload_flow_depth) > 0) {
            payload_flow = 0
        } else {
            payload_flow_depth = flow_depth
        }
        return
    }
    # A masked flow-style env value can wrap onto the following lines when
    # its quoted scalar does not close on the value line; the wrapped part
    # is masked up to the delimiter that closes the item, so no fragment of
    # the value survives. A quoted scalar is masked through its closing
    # quote instead, because a comma or brace inside the value is data, not
    # the end of the item.
    if (env_flow_cont) {
        if (env_flow_quote != "") {
            quote_end = closing_quote($0, env_flow_quote)
            if (quote_end) {
                $0 = "<redacted>" substr($0, quote_end + 1)
                env_flow_cont = 0
                env_flow_quote = ""
            } else {
                $0 = "<redacted>"
            }
        } else if (match($0, /[,}]/)) {
            $0 = "<redacted>" substr($0, RSTART)
            env_flow_cont = 0
        } else {
            $0 = "<redacted>"
        }
        print; return
    }
    if (kind == "Secret" && /^(data|stringData):[[:space:]]*(#.*)?$/) { in_payload = 1; print; return }
    # A Secret data/stringData value can also be a flow map on one line or
    # across several; the block-form rule above only matches an empty key
    # line. The whole map body is replaced by a single <redacted> entry so
    # the printed manifest stays valid YAML, and any continuation lines are
    # dropped.
    if (kind == "Secret" && /^(data|stringData):[[:space:]]*\{/) {
        match($0, /^(data|stringData):[[:space:]]*\{/)
        print substr($0, 1, RLENGTH) "<redacted>}"
        if (flow_close(substr($0, RLENGTH + 1), 1) == 0) {
            payload_flow = 1
            payload_flow_depth = flow_depth
        }
        return
    }
    if (endpoint_configmap && /^data:[[:space:]]*(#.*)?$/) { in_payload = 1; print; return }
    if (configmap_document && /^(data|binaryData):[[:space:]]*(#.*)?$/) { configmap_data = 1; configmap_binary = ($0 ~ /^binaryData:/); print; return }
    if (/^[^ #]/) { in_payload = 0; configmap_data = 0; configmap_binary = 0 }
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
    # A ConfigMap data value may be a whole configuration file: any
    # block-scalar key, not only a credential-shaped one, can carry a
    # password or token on one of its lines. The body is file content, not
    # manifest structure, so a credential assignment is masked in place and
    # every other line stays readable for review; the block ends at the
    # first line at or shallower than the key, which resumes normal
    # processing.
    if (config_file_block) {
        match($0, /^ */)
        if ($0 !~ /^ *$/ && RLENGTH <= config_file_indent) {
            config_file_block = 0
            file_nested = 0
        } else {
            # A block scalar value under a masked credential key is part of
            # that key value, so its body is dropped with it; the nested
            # block ends at the first non-blank line at or shallower than
            # the key.
            if (file_nested) {
                match($0, /^ */)
                if ($0 ~ /^ *$/ || RLENGTH > file_nested_indent) return
                file_nested = 0
            }
            file_line = $0
            file_prefix = ""
            file_body = file_line
            # Shell scripts and YAML lists put a prefix before the
            # assignment (`export DB_PASSWORD=x`, `- password: x`). Strip
            # indentation and any such prefix while matching the key, and
            # keep them in the printed line.
            while (file_body != "") {
                if (file_body ~ /^[[:space:]]+/) {
                    match(file_body, /^[[:space:]]+/)
                } else if (file_body ~ /^(-|export)[[:space:]]+/) {
                    match(file_body, /^(-|export)[[:space:]]+/)
                } else {
                    break
                }
                file_prefix = file_prefix substr(file_body, 1, RLENGTH)
                file_body = substr(file_body, RLENGTH + 1)
            }
            if (file_body ~ /^["\047]?[A-Za-z0-9_.-]+["\047]?[[:space:]]*[:=][[:space:]]*[^[:space:]]/) {
                file_key = file_body
                sub(/^["\047]?/, "", file_key)
                sub(/["\047]?[[:space:]]*[:=][[:space:]]*.*$/, "", file_key)
                if (credential_file_key(file_key)) {
                    # Keep everything through the separator and any spacing
                    # after it, so `password: x`, `password=x` and
                    # `"token": "x"` all keep their shape.
                    if (match(file_body, /[:=][[:space:]]*/)) {
                        cut = RSTART + RLENGTH - 1
                        # A block scalar indicator (| or >, with any chomping
                        # suffix) means the value continues on deeper-indented
                        # lines, which are dropped with the key.
                        if (substr(file_body, cut + 1) ~ /^[|>]/) {
                            match(file_line, /^ */)
                            file_nested_indent = RLENGTH
                            file_nested = 1
                        }
                        file_body = substr(file_body, 1, cut) "<redacted>"
                    }
                } else if (tolower(file_key) ~ /(^|[_.-])(host|hostname|server|addr|address|endpoint|broker|peer|node)([_.-]|$)/) {
                    # An endpoint-shaped key in a file line carries a
                    # hostname; a dotted or port-bearing value is a host or
                    # address, while a bare service name
                    # (`host = netbox-db`) stays readable.
                    if (match(file_body, /[:=][[:space:]]*/)) {
                        cut = RSTART + RLENGTH - 1
                        if (substr(file_body, cut + 1) ~ /[.:]/)
                            file_body = substr(file_body, 1, cut) "<redacted>"
                    }
                }
            }
            # Credentials embedded as URL userinfo are masked whatever
            # the key is, because a neutral key such as uri can still
            # carry a password in a connection string. An `@` past the
            # end of the authority is query data, not userinfo.
            gsub(/:\/\/[^\/[:space:]@?#]+@/, "://<redacted>@", file_body)
            # The same line can carry endpoint data the line-start rule
            # above does not see: a URL host, an internal-shaped hostname,
            # an embedded credential assignment, or a credential in a URL
            # query parameter. Each is masked in place so the rest of the
            # file stays readable.
            file_body = mask_url_hosts(file_body)
            file_body = mask_internal_hostnames(file_body)
            file_body = mask_embedded_credentials(file_body)
            file_body = mask_query_credentials(file_body)
            # An inline JSON object line has no leading key for the rule
            # above; its credential-shaped fields are masked in place.
            file_body = mask_json_credentials(file_body)
            print file_prefix file_body
            return
        }
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
    # An env value is masked when the document pre-scan paired it with a
    # sensitive name, whatever the key order inside the item and whether
    # the item is block- or flow-style. A block-scalar value keeps its
    # body on deeper-indented lines, which are dropped with the value.
    if (env_secret[line_no]) {
        if ($0 ~ /^[[:space:]]*- \{/ || env_flow[line_no]) {
            # Flow item: keep the closing brace and any fields after the
            # value, and mask only the value scalar (quoted or plain). The
            # key needs a flow-key boundary so a sibling field such as
            # `subvalue:` cannot shadow the real value; the opening brace
            # of the item counts as a boundary for a value key written
            # first. The scalar runs through its own closing quote, so an
            # escaped double quote or a doubled single quote cannot end
            # the mask early and expose the rest of the value. A scalar
            # that does not close on this line continues below and is
            # masked there.
            if (match($0, /[{,[:space:]]value:[[:space:]]*/)) {
                flow_head = substr($0, 1, RSTART + RLENGTH - 1)
                flow_rest = substr($0, RSTART + RLENGTH)
                flow_len = scalar_length(flow_rest, "^[^,}]*")
                flow_quote = substr(flow_rest, 1, 1)
                $0 = flow_head "<redacted>" substr(flow_rest, flow_len + 1)
                env_flow_quote = ""
                if (substr(flow_rest, flow_len + 1) !~ /^[[:space:]]*[,}]/) {
                    env_flow_cont = 1
                    # A quoted scalar that does not close on this line is
                    # masked through its closing quote on a later line, so
                    # a comma or brace inside the value does not end it.
                    if ((flow_quote == "\"" || flow_quote == "\047") \
                        && closing_quote(substr(flow_rest, 2), flow_quote) == 0)
                        env_flow_quote = flow_quote
                }
            }
        } else if ($0 ~ /^[[:space:]]*(- )?value:([[:space:]]|$)/) {
            # A masked block value ends its line; an empty value puts the
            # real value on the following lines, and a plain or quoted
            # scalar can wrap onto deeper-indented lines, so every line
            # deeper than the key belongs to the value until a line at or
            # shallower than the key returns. The key indent counts the
            # item dash as structure, so a `- value:` line does not
            # swallow a sibling `name:` at the key indent as if it were
            # part of the value.
            env_block_indent = key_indent($0)
            env_block = 1
            sub(/value:.*/, "value: <redacted>")
        }
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
    # Credential-shaped ConfigMap data entries are masked for the same
    # reason env entries are: a caller values overlay can render a
    # ConfigMap (for example through the NetBox chart extraDeploy) whose
    # data carries a token or password, and the dry run prints whole
    # manifests. The document pre-scan identifies ConfigMaps even when a
    # data key precedes its identity, and a block-scalar body is dropped
    # with its key so only the key and the rest of the data stay readable.
    if (configmap_data && $0 ~ /^  [^ :][^:]*: ./) {
        config_key = $0
        sub(/:.*/, "", config_key)
        # Drop the entry indent so a bare `key` entry matches `(^|_)key$`.
        sub(/^[[:space:]]+/, "", config_key)
        if (credential_name(config_key)) {
            if ($0 ~ /: [|>]/) {
                match($0, /^ */)
                config_block_indent = RLENGTH
                config_block = 1
            }
            sub(/: .*/, ": <redacted>")
        }
    }
    # Any other ConfigMap data block scalar is a configuration-file payload;
    # its body is scanned line by line by the file rule above until the
    # block ends.
    if (configmap_data && !config_block && $0 ~ /^  [^ :][^:]*: [|>]/) {
        match($0, /^ */)
        config_file_indent = RLENGTH
        config_file_block = 1
        file_nested = 0
    }
    # A ConfigMap data value can also be that configuration file collapsed
    # onto one line (`netbox.conf: host = db password = x`), which the
    # block-scalar rule above never sees. A credential anywhere in the
    # value makes the whole line secret-bearing, so the value is masked as
    # a unit; a single-line value without a credential stays readable.
    if (configmap_data && !configmap_binary && !config_block \
        && $0 ~ /^  [^ :][^:]*: [^|>]/) {
        config_key = $0
        sub(/:.*/, "", config_key)
        sub(/^[[:space:]]+/, "", config_key)
        config_val = $0
        sub(/^[^:]*:[[:space:]]*/, "", config_val)
        if (!credential_name(config_key) \
            && tolower(config_key) !~ /(url|host|addr|endpoint)/ \
            && has_inline_credential(config_val))
            sub(/: .*/, ": <redacted>")
    }
    if (in_payload) {
        # Block-scalar body lines (indent deeper than the entry keys) are
        # dropped outright; single-line entry values are masked in place.
        if ($0 ~ /^   +[^ ]/) return
        if ($0 ~ /^  [^ :][^:]*: ./) sub(/: .*/, ": <redacted>")
    }
    # Credentials embedded as URL userinfo are masked on every line,
    # whatever the key or the container, because a neutral key such as
    # uri or DATABASE_URI can still carry a password in a connection
    # string. An `@` past the end of the authority is query data.
    gsub(/:\/\/[^\/[:space:]@?#]+@/, "://<redacted>@")
    print
}
/^---([[:space:]]+#.*)?[[:space:]]*$/ { separator = $0; flush_document(); print separator; next }
{ document[++document_length] = $0 }
END { flush_document() }
'
