#!/usr/bin/env bash

# The installer must reject invalid inputs before any cluster mutation or
# readiness wait, naming the offending field and an actionable remedy.
#
# Section A proves the wiring with stubbed helm/oc/kubectl/kind binaries: the
# offline render runs first, and a failing render aborts the install with no
# mutating command invoked -- including under `make -j`. It runs against a
# throwaway copy of the installer so chart-dependency recipes cannot touch
# this checkout's build artifacts.
#
# Section B proves the schema rejections with a real Helm render, asserting
# the offending field and the violated constraint so an unrelated rendering
# failure cannot satisfy a negative test.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALLER_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
OSAC_CHART_DIR="${INSTALLER_DIR}/charts/osac"
INFRA_CHART_DIR="${INSTALLER_DIR}/charts/osac-infra"
HELM_BIN=${HELM_BIN:-helm}
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# Print an error to stderr and abort the suite with a non-zero status.
fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Section A: gate ordering and no-mutation-on-failure (stubbed commands)
# ---------------------------------------------------------------------------

SANDBOX="${TMP_DIR}/installer"
STUB_BIN="${TMP_DIR}/bin"
LOG="${TMP_DIR}/commands.log"
cp -a "${INSTALLER_DIR}" "${SANDBOX}"
mkdir -p "${STUB_BIN}"
: >"${LOG}"

# Write an executable stub binary named $1 whose body is the heredoc on stdin.
write_stub() {
  local name=$1
  {
    echo '#!/usr/bin/env bash'
    cat
  } >"${STUB_BIN}/${name}"
  chmod +x "${STUB_BIN}/${name}"
}

# Shared stub logger: append "name arg..." to MOCK_LOG with the value
# after --set/--set-string redacted, so a secret-bearing override passed
# through EXTRA_HELM_ARGS cannot land in the log. Assertions only match
# command names and flag spellings, never the redacted values.
write_stub mock-log <<'STUB'
#!/usr/bin/env bash
set -eu
name=$1
shift
redacted=()
prev=
for arg in "$@"; do
  case "${prev}" in
    --set|--set-string) arg='<redacted>' ;;
  esac
  case "${arg}" in
    --set=*|--set-string=*) arg='--set=<redacted>' ;;
  esac
  redacted+=("${arg}")
  prev=${arg}
done
printf '%s %s\n' "${name}" "${redacted[*]}" >>"${MOCK_LOG}"
STUB

# helm: log every invocation; MOCK_TEMPLATE_FAIL=1 makes offline renders fail
# the way a schema violation would. `version` feeds the Makefile's Helm
# major/minor detection.
write_stub helm <<'STUB'
mock-log helm "$@"
case "$1" in
  version) echo "v3.18.0+gstub" ;;
  template)
    if [ "${MOCK_TEMPLATE_FAIL:-0}" = 1 ]; then
      echo "Error: values don't meet the specifications of the schema" >&2
      exit 1
    fi
    ;;
esac
exit 0
STUB

# oc: read-only lookups the gate performs before rendering (cluster version
# and ingress domain). Everything else is logged and succeeds.
write_stub oc <<'STUB'
mock-log oc "$@"
case "$*" in
  *clusterversion*) echo "4.22.14" ;;
  *ingresses.config/cluster*) echo "apps.example.com" ;;
esac
exit 0
STUB

write_stub kubectl <<'STUB'
mock-log kubectl "$@"
exit 0
STUB

write_stub kind <<'STUB'
mock-log kind "$@"
exit 0
STUB

mutation_commands='helm upgrade|kind create|kubectl apply|oc create|oc apply'

assert_prevalidation_commands() {
  local label=$1 command
  while IFS= read -r command; do
    case "${command}" in
      'helm version '*|'helm dependency build '*|'helm template '*) ;;
      'helm --repository-config /dev/null dependency build charts/osac') ;;
      'helm repo add topolvm https://topolvm.github.io/topolvm/ --force-update') ;;
      'helm repo add netbox https://netbox-community.github.io/netbox-chart/ --force-update') ;;
      'helm repo add awx-operator https://ansible-community.github.io/awx-operator-helm/ --force-update') ;;
      'oc get clusterversion version -o jsonpath={.status.desired.version}') ;;
      'oc get ingresses.config/cluster -o jsonpath={.spec.domain}') ;;
      *) fail "${label}: command not permitted before validation: ${command}" ;;
    esac
  done <"${LOG}"
}

# The first chart render must precede the first mutating command in every
# supported installation entry point's expansion.
assert_renders_first() {
  local target=$1
  shift
  local plan="${TMP_DIR}/${target//\//_}.plan"
  MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory -n "${target}" "$@" \
    >"${plan}" 2>"${TMP_DIR}/plan.err" || fail "make -n ${target} $* failed"
  local first_render first_mutation
  first_render=$(grep -n 'helm template' "${plan}" | head -1 | cut -d: -f1)
  first_mutation=$(grep -nE "${mutation_commands}" "${plan}" | head -1 | cut -d: -f1)
  [ -n "${first_render}" ] || fail "${target} ($*): no offline render in the plan"
  if [ -n "${first_mutation}" ] && [ "${first_mutation}" -lt "${first_render}" ]; then
    fail "${target} ($*): a cluster mutation precedes the input validation render"
  fi
}

assert_renders_first install PLATFORM=kind PROFILE=dev NS=osac
assert_renders_first install PLATFORM=openshift PROFILE=dev NS=osac
assert_renders_first install-infra PLATFORM=kind PROFILE=dev NS=osac
assert_renders_first install-infra PLATFORM=openshift PROFILE=dev NS=osac
assert_renders_first install-osac PLATFORM=kind PROFILE=dev NS=osac
assert_renders_first install-osac PLATFORM=openshift PROFILE=dev NS=osac
assert_renders_first install-devstack PLATFORM=kind PROFILE=dev-full NS=osac
# install-multicluster guards its profile and remote kubeconfig at parse time.
REMOTE_KUBECONFIG="${LOG}" assert_renders_first install-multicluster \
  PLATFORM=openshift PROFILE=vmaas-ci NS=osac

# Entry points that never render the devstack chart must not build its
# external (awx-operator) dependencies: the gate adds no network dependency
# the entry point did not already have.
assert_no_devstack_deps() {
  local label=$1
  shift
  local plan="${TMP_DIR}/no-devstack-${label}.plan"
  MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory -n "$@" \
    >"${plan}" 2>"${TMP_DIR}/no-devstack-${label}.err" \
    || fail "make -n $* failed"
  if grep -Eq 'awx-operator|helm-devstack-deps' "${plan}"; then
    fail "${label}: the gate builds devstack dependencies it never renders"
  fi
}

assert_no_devstack_deps kind-dev install PLATFORM=kind PROFILE=dev NS=osac
assert_no_devstack_deps openshift-osac install-osac PLATFORM=openshift \
  PROFILE=caas-ci NS=osac
assert_no_devstack_deps multicluster install-multicluster \
  PLATFORM=openshift PROFILE=vmaas-ci NS=osac REMOTE_KUBECONFIG="${LOG}"

# install-multicluster's gate must validate the multicluster infra overlay
# too: the recipe only passes it to the recursive install-infra, which runs
# after prepare-remote-cluster has already changed the remote cluster.
# Continuation lines are joined so the render command and its values flags
# match on one line, and only the plan region before the first recursive
# make is checked -- that is the gate, not the sub-make's own renders.
# Join make -n recipe continuation lines (trailing backslash) so a command
# and its flag lines can be matched as one logical line.
join_continuations() {
  awk '/\\$/ { sub(/\\$/, ""); acc = acc $0 " "; next }
       { print acc $0; acc = "" }'
}

mc_plan="${TMP_DIR}/multicluster.plan"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory -n install-multicluster \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    >"${mc_plan}" 2>/dev/null || fail "make -n install-multicluster failed"
sed -n '1,/prepare-remote-cluster/p' "${mc_plan}" | join_continuations \
  | grep 'helm template osac-infra' | grep -q 'multicluster-infra.yaml' \
  || fail "install-multicluster: the gate does not render the multicluster overlay"

# Gate/install parity for INFRA_HELM_ARGS: every helm command touching
# osac-infra or osac-deps in the OpenShift install plan -- the gate's
# renders, the EVPN deadline render, and the upgrades -- must apply the
# variable, like the Kind branch already does. Without it, the gate would
# validate a different value set than the install applies (e.g. an overlay
# at an invalid value overridden by INFRA_HELM_ARGS would pass the gate and
# fail the install).
infra_args_plan="${TMP_DIR}/infra-args.plan"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory -n install-infra \
    PLATFORM=openshift PROFILE=caas-ci NS=osac \
    INFRA_HELM_ARGS='--set topolvm.enabled=true' \
    >"${infra_args_plan}" 2>/dev/null || fail "make -n install-infra (openshift) failed"
infra_arg_cmds=$(join_continuations <"${infra_args_plan}" \
  | sed -E 's/(helm (template|upgrade))/\n\1/g' \
  | grep -E 'helm (template|upgrade).* osac-(infra|deps) ' || true)
[ -n "${infra_arg_cmds}" ] \
  || fail "install-infra (openshift): no osac-infra/osac-deps helm commands in the plan"
while IFS= read -r infra_cmd; do
  case "${infra_cmd}" in
    *topolvm.enabled=true*) ;;
    *) fail "install-infra (openshift): INFRA_HELM_ARGS missing from: ${infra_cmd}" ;;
  esac
done <<<"${infra_arg_cmds}"

# Gate/install parity for OIDC_IDP_CA_HELM_ARGS: every helm command
# touching osac-infra in the install plan -- the gate's render, the
# seed-check render, the EVPN deadline render, and the upgrade -- must
# apply the same CA input, so a CA file (or a values-file caPem it
# overrides) is validated identically everywhere and an unreadable or
# schema-breaking input fails before any cluster change.
for ca_platform in kind openshift; do
  ca_plan="${TMP_DIR}/oidc-ca-${ca_platform}.plan"
  MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory -n install-infra \
    PLATFORM="${ca_platform}" PROFILE=dev NS=osac \
    OIDC_IDP_CA_FILE=/nonexistent-ca.pem \
    >"${ca_plan}" 2>/dev/null || fail "make -n install-infra (${ca_platform}) failed"
  ca_cmds=$(join_continuations <"${ca_plan}" \
    | sed -E 's/(helm (template|upgrade))/\n\1/g' \
    | grep -E 'helm (template|upgrade).* osac-infra ' || true)
  [ -n "${ca_cmds}" ] \
    || fail "install-infra (${ca_platform}): no osac-infra helm commands in the plan"
  while IFS= read -r ca_cmd; do
    case "${ca_cmd}" in
      *--set-file\ keycloak.oidcIdpTrust.caPem*) ;;
      *) fail "install-infra (${ca_platform}): OIDC IdP CA input missing from: ${ca_cmd}" ;;
    esac
  done <<<"${ca_cmds}"
  join_continuations <"${ca_plan}" | grep 'netbox_seed_check osac-infra' \
    | grep -q -- '--set-file keycloak.oidcIdpTrust.caPem' \
    || fail "install-infra (${ca_platform}): the seed-check render omits the OIDC IdP CA input"
done

# Cluster-lookup output must reach Make only through a validating filter:
# the lookups feed $(eval), so a compromised or misbehaving API response
# carrying Make syntax must fail the gate instead of executing. The
# sentinel file proves no injection ran.
echo "checking injection (Make syntax in cluster lookups fails the gate)"
inj_bin="${TMP_DIR}/inj-bin"
cp -a "${STUB_BIN}" "${inj_bin}"
inj_sentinel="${TMP_DIR}/injection-ran"
cat >"${inj_bin}/oc" <<STUB
#!/usr/bin/env bash
case "\$*" in
  *clusterversion*) printf '4\$(shell touch \${INJECTION_SENTINEL}).22.14\n' ;;
  *ingresses.config/cluster*) printf '\$(shell touch \${INJECTION_SENTINEL})apps.example.com\n' ;;
esac
exit 0
STUB
chmod +x "${inj_bin}/oc"
: >"${LOG}"
if INJECTION_SENTINEL="${inj_sentinel}" MOCK_LOG="${LOG}" PATH="${inj_bin}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
  PLATFORM=openshift PROFILE=dev NS=osac \
  >"${TMP_DIR}/inj.out" 2>"${TMP_DIR}/inj.err"; then
  fail "injection: the gate accepted Make-syntax-bearing cluster lookups"
fi
[ ! -e "${inj_sentinel}" ] \
  || fail "injection: cluster-lookup output executed as Make code"
grep -q 'could not determine the OpenShift version' "${TMP_DIR}/inj.err" \
  || fail "injection: the failure did not name the version lookup"
assert_prevalidation_commands injection

# NS is interpolated into recipe command text after the gate, so the gate
# must reject a namespace carrying shell metacharacters before any of that
# text is expanded. The sentinel file proves nothing executed.
echo "checking ns-injection (metacharacters in NS fail the gate)"
ns_sentinel="${TMP_DIR}/ns-injection-ran"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
  PLATFORM=kind PROFILE=dev "NS=osac;touch ${ns_sentinel}" \
  >"${TMP_DIR}/ns.out" 2>"${TMP_DIR}/ns.err"; then
  fail "ns-injection: the gate accepted a metacharacter-bearing NS"
fi
[ ! -e "${ns_sentinel}" ] \
  || fail "ns-injection: NS executed as shell code"
grep -q 'NS must be a lowercase DNS label' "${TMP_DIR}/ns.err" \
  || fail "ns-injection: the failure did not name the namespace rule"
assert_prevalidation_commands ns-injection

# The dry run prints rendered manifests to the terminal and to collected
# CI logs, so every dry-run render is piped through the Secret-payload
# redactor; an unpiped render could leak credentials supplied through a
# values overlay.
echo "checking dry-run-redaction wiring (every dry-run render is redacted)"
for dry_platform in kind openshift; do
  dry_plan="${TMP_DIR}/dryrun-${dry_platform}.plan"
  MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory -n install-dry-run \
    PLATFORM="${dry_platform}" PROFILE=dev NS=osac \
    DRY_RUN_CLUSTER_DOMAIN=apps.example.com DRY_RUN_OCP_VERSION=4.22 \
    >"${dry_plan}" 2>/dev/null \
    || fail "make -n install-dry-run (${dry_platform}) failed"
  dry_renders=$(join_continuations <"${dry_plan}" | grep -c 'helm template')
  dry_redacted=$(join_continuations <"${dry_plan}" | grep 'helm template' \
    | grep -c 'redact-secret-values')
  [ "${dry_renders}" -gt 0 ] \
    || fail "install-dry-run (${dry_platform}): no renders in the plan"
  [ "${dry_renders}" = "${dry_redacted}" ] \
    || fail "install-dry-run (${dry_platform}): a render skips Secret redaction"
done

# Remote-cluster inputs: the gate must reject invalid static identifiers
# before any cluster mutation -- install-osac's own re-check runs only after
# install-infra and namespace creation have already changed the cluster.
remote_bad_out="${TMP_DIR}/remote-bad.out" remote_bad_err="${TMP_DIR}/remote-bad.err"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install-osac \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    REMOTE_KUBECONFIG="${LOG}" REMOTE_KUBECONFIG_SECRET_NAME='Bad_Name' \
    >"${remote_bad_out}" 2>"${remote_bad_err}"; then
  fail "remote-identifier: install-osac succeeded with an invalid secret name"
fi
grep -q 'REMOTE_KUBECONFIG_SECRET_NAME must be a DNS subdomain' "${remote_bad_err}" \
  || fail "remote-identifier: the failure did not name the identifier rule"
assert_prevalidation_commands remote-identifier

# The identifiers reach the gate's validator through the environment, not
# through Make expansion into its quoted bash -c string: a quote-bearing
# value is rejected as an invalid DNS subdomain instead of breaking out of
# the quoting and running as shell code. The mutation log doubles as the
# canary: the injected command is an oc create, so execution would show.
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install-osac \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    REMOTE_KUBECONFIG="${LOG}" \
    REMOTE_KUBECONFIG_SECRET_NAME="a'; oc create namespace pwned; '" \
    >"${TMP_DIR}/remote-inj.out" 2>"${TMP_DIR}/remote-inj.err"; then
  fail "remote-injection: install-osac succeeded with a quote-bearing name"
fi
grep -q 'REMOTE_KUBECONFIG_SECRET_NAME must be a DNS subdomain' "${TMP_DIR}/remote-inj.err" \
  || fail "remote-injection: the value did not reach the validator as a literal"
assert_prevalidation_commands remote-injection

# The gate's osac-chart render and install-osac's upgrade share the same
# remote-cluster kubeconfig argument construction (REMOTE_CLUSTER_HELM_ARGS),
# so the gate validates the final merged values the install applies.
remote_plan="${TMP_DIR}/remote-args.plan"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory -n install-osac \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    >"${remote_plan}" 2>/dev/null || fail "make -n install-osac (remote) failed"
join_continuations <"${remote_plan}" | grep 'render_osac_chart_offline' \
  | grep -q 'operator.remoteClusterKubeconfigSecretName=osac-remote-kubeconfig' \
  || fail "validate-inputs: the gate render omits the remote-cluster args"
join_continuations <"${remote_plan}" | grep 'helm upgrade --install osac ' \
  | grep -q 'operator.remoteClusterKubeconfigSecretName=osac-remote-kubeconfig' \
  || fail "install-osac: the upgrade omits the remote-cluster args"

# The remote-cluster flags must also resolve in the same order everywhere:
# the gate's render applies them after EXTRA_HELM_ARGS like install-osac's
# upgrade does, so a caller overriding a remote-cluster flag through
# EXTRA_HELM_ARGS sees the gate validate exactly what the install applies
# (Helm's last --set-string for a key wins).
remote_order_plan="${TMP_DIR}/remote-order.plan"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory -n install-osac \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    EXTRA_HELM_ARGS='--set-string operator.remoteClusterKubeconfigSecretName=caller-override' \
    >"${remote_order_plan}" 2>/dev/null || fail "make -n install-osac (remote order) failed"
for remote_cmd in 'render_osac_chart_offline' 'helm upgrade --install osac '; do
  join_continuations <"${remote_order_plan}" | grep "${remote_cmd}" \
    | grep -q 'caller-override.*operator.remoteClusterKubeconfigSecretName=osac-remote-kubeconfig' \
    || fail "remote-flag order: ${remote_cmd} does not apply EXTRA_HELM_ARGS before the remote-cluster flags"
done

# The gate's osac-chart render goes through render_osac_chart_offline with
# the render-only placeholder token: the function applies the placeholder
# only when the merged render has no NetBox token at all, never over a
# caller-supplied value from --set, --set-string, or a values file. The
# bridge is legitimate only when this install's infra values deploy the
# netbox-token-seed hook, so the gate runs netbox_seed_check first, in the
# same recipe line (make recipe lines are separate shells).
join_continuations <"${remote_plan}" | grep 'render_osac_chart_offline' \
  | grep -q 'offline-validation-placeholder' \
  || fail "validate-inputs: the gate render must bridge the NetBox token via render_osac_chart_offline"
join_continuations <"${remote_plan}" | grep 'netbox_seed_check osac-infra' \
  | grep -q 'render_osac_chart_offline' \
  || fail "validate-inputs: the gate must run netbox_seed_check before the bridged render"

# install-devstack rejects a wrong profile at parse time, before the gate's
# cluster lookups or renders, so the user sees the actual mistake.
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory -n install-devstack \
    PLATFORM=kind PROFILE=dev NS=osac \
    >"${TMP_DIR}/devstack-guard.out" 2>"${TMP_DIR}/devstack-guard.err"; then
  fail "install-devstack accepted PROFILE=dev"
fi
grep -q 'install-devstack requires PROFILE=dev-full' \
  "${TMP_DIR}/devstack-guard.err" \
  || fail "install-devstack did not name the profile requirement"

# An invalid configuration must abort the install before any cluster
# mutation -- serially and in parallel.
assert_no_mutation_on_failure() {
  local label=$1
  shift
  : >"${LOG}"
  local out="${TMP_DIR}/fail-${label}.out" err="${TMP_DIR}/fail-${label}.err"
  if MOCK_LOG="${LOG}" MOCK_TEMPLATE_FAIL=1 PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory "$@" \
    >"${out}" 2>"${err}"; then
    fail "${label}: install succeeded despite invalid inputs"
  fi
  grep -q 'helm template' "${LOG}" || fail "${label}: the offline render never ran"
  assert_prevalidation_commands "${label}"
  grep -q 'no cluster changes were made' "${err}" \
    || fail "${label}: the failure did not state that no cluster changes were made"
}

assert_no_mutation_on_failure serial install PLATFORM=kind PROFILE=dev NS=osac
assert_no_mutation_on_failure parallel install -j4 PLATFORM=kind PROFILE=dev NS=osac
assert_no_mutation_on_failure openshift install PLATFORM=openshift PROFILE=dev NS=osac
assert_no_mutation_on_failure direct-infra install-infra PLATFORM=openshift PROFILE=dev NS=osac
assert_no_mutation_on_failure direct-osac install-osac PLATFORM=kind PROFILE=dev NS=osac
assert_no_mutation_on_failure multicluster install-multicluster \
  PLATFORM=openshift PROFILE=vmaas-ci NS=osac REMOTE_KUBECONFIG="${LOG}"

echo "input-validation gate wiring passed"

# ---------------------------------------------------------------------------
# Section B: schema rejections with a real Helm render
# ---------------------------------------------------------------------------

COMMON_ARGS=(template osac "${OSAC_CHART_DIR}"
  --values "${OSAC_CHART_DIR}/ci/default-values.yaml")
INFRA_ARGS=(template osac-infra "${INFRA_CHART_DIR}"
  --values "${INSTALLER_DIR}/values/dev/kind-infra.yaml")

# Render the osac chart with the given extra helm args and expect success.
render_success() {
  local name=$1
  shift
  echo "checking ${name} (expected success)"
  "${HELM_BIN}" "${COMMON_ARGS[@]}" "$@" >/dev/null
}

# Render the osac-infra chart with the given extra helm args; expect success.
render_infra_success() {
  local name=$1
  shift
  echo "checking ${name} (expected success)"
  "${HELM_BIN}" "${INFRA_ARGS[@]}" "$@" >/dev/null
}

# Render the osac chart expecting failure, requiring stderr to match the
# pattern (the offending field and violated constraint) so an unrelated
# rendering failure cannot satisfy a negative test.
render_failure_matching() {
  local name=$1 pattern=$2
  shift 2
  local error="${TMP_DIR}/${name}.stderr"
  echo "checking ${name} (expected failure matching ${pattern@Q})"
  if "${HELM_BIN}" "${COMMON_ARGS[@]}" "$@" >/dev/null 2>"${error}"; then
    echo "ERROR: ${name} unexpectedly rendered successfully" >&2
    exit 1
  fi
  if ! grep -Eiq -- "${pattern}" "${error}"; then
    echo "ERROR: ${name} failed without the expected message pattern" >&2
    cat "${error}" >&2
    exit 1
  fi
}

# Render the osac-infra chart expecting failure with stderr matching the
# pattern; the infra counterpart of render_failure_matching.
render_infra_failure_matching() {
  local name=$1 pattern=$2
  shift 2
  local error="${TMP_DIR}/${name}.stderr"
  echo "checking ${name} (expected failure matching ${pattern@Q})"
  if "${HELM_BIN}" "${INFRA_ARGS[@]}" "$@" >/dev/null 2>"${error}"; then
    echo "ERROR: ${name} unexpectedly rendered successfully" >&2
    exit 1
  fi
  if ! grep -Eiq -- "${pattern}" "${error}"; then
    echo "ERROR: ${name} failed without the expected message pattern" >&2
    cat "${error}" >&2
    exit 1
  fi
}

# A valid configuration still renders end to end (AC: supported valid
# configurations are unaffected by the gate).
render_success valid-defaults
render_infra_success infra-valid-defaults

# Retry counts and POSIX IDs accept zero (no retries, root) but never
# negative values. Minimum-constraint wording differs across Helm
# versions: 3.18 prints "Must be greater than or equal to 0" while 3.22
# (what CI installs) prints "minimum: got -1, want 0"; patterns accept
# both, in the dotted-path (Helm 3) and JSON-pointer (newer) spellings.
render_failure_matching \
  backoff-limit-negative \
  '(aap\.bootstrap\.backoffLimit|/aap/bootstrap/backoffLimit).*(greater than or equal to 0|minimum: got -1, want 0)' \
  --set aap.bootstrap.backoffLimit=-1

render_success \
  backoff-limit-zero \
  --set aap.bootstrap.backoffLimit=0

for field in runAsUser runAsGroup fsGroup; do
  render_infra_failure_matching \
    "vault-${field}-negative" \
    "(bundledVault\\.podSecurityContext\\.${field}|/bundledVault/podSecurityContext/${field}).*(greater than or equal to 0|minimum: got -1, want 0)" \
    --set "bundledVault.podSecurityContext.${field}=-1"
done

render_infra_success \
  vault-runasuser-zero \
  --set bundledVault.podSecurityContext.runAsUser=0

render_infra_success \
  vault-runasgroup-zero \
  --set bundledVault.podSecurityContext.runAsGroup=0

render_infra_success \
  vault-fsgroup-zero \
  --set bundledVault.podSecurityContext.fsGroup=0

# Chart-owned objects are closed: an unknown key is rejected instead of
# being silently ignored.
render_failure_matching \
  fulfillment-trust-unknown-key \
  '(global\.fulfillmentTrust|/global/fulfillmentTrust).*additional propert(y|ies).*unknownKey.*(is )?not allowed' \
  --set global.fulfillmentTrust.unknownKey=1

# bmaas-netbox-ci is a valid profile the gate must not block: it relies on
# the infra chart's netbox-token-seed hook to create the NetBox token Secret
# during a real install, and offline rendering cannot see cluster Secrets
# (helm template's lookup returns nil), so the raw render fails the
# lookup-dependent branch. The gate bridges exactly that failure through
# render_osac_chart_offline (scripts/lib.sh) with a render-only placeholder
# (NETBOX_OFFLINE_PLACEHOLDER in the Makefile; it must match the value asserted
# below) that is never passed to an installation -- and only when
# netbox_seed_check first saw this install's infra values deploy the seed
# hook. The hostname --sets mirror the OpenShift gate branch -- the
# profile's supported platform; on Kind the install itself rejects the
# profile's empty hostnames, gate and install alike.
NETBOX_PROFILE_ARGS=(
  -f "${INSTALLER_DIR}/values/bmaas-ci/instance.yaml"
  -f "${INSTALLER_DIR}/values/bmaas-netbox-ci/instance.yaml"
  --set service.externalHostname=fulfillment-api-osac.example.com
  --set service.internalHostname=fulfillment-internal-api-osac.example.com
  --set global.clusterDomain=example.com
)

render_failure_matching \
  netbox-profile-raw-render \
  'netbox\.tokenValue is required when Secret' \
  "${NETBOX_PROFILE_ARGS[@]}"

# The gate's osac-chart render goes through render_osac_chart_offline, so
# the tests below exercise the same code path the gate uses.
source "${SCRIPT_DIR}/lib.sh"
netbox_gate_err="${TMP_DIR}/netbox-gate.err"

# netbox_seed_check decides whether the bridge is legitimate at all: the
# netbox profile's infra values deploy the seed hook, bmaas-ci's do not.
echo "checking netbox-seed-hook-present (the netbox profile's infra deploys it)"
netbox_seed_check osac-infra "${INFRA_CHART_DIR}" \
  --values "${INSTALLER_DIR}/values/bmaas-ci/infra.yaml" \
  --values "${INSTALLER_DIR}/values/bmaas-netbox-ci/infra.yaml" \
  --set osacNamespace=osac
[ "${NETBOX_TOKEN_SEEDED}" = "1" ] \
  || fail "netbox-seed-hook-present: the netbox profile's infra render deploys no netbox-token-seed"
[ "${NETBOX_SEED_SECRET_NAME}" = "netbox-api-token" ] \
  || fail "netbox-seed-hook-present: wrong seed Secret name ${NETBOX_SEED_SECRET_NAME}"
[ "${NETBOX_SEED_SECRET_NS}" = "osac" ] \
  || fail "netbox-seed-hook-present: wrong seed Secret namespace ${NETBOX_SEED_SECRET_NS}"
[ "${NETBOX_SEED_SECRET_KEY}" = "token" ] \
  || fail "netbox-seed-hook-present: wrong seed Secret key ${NETBOX_SEED_SECRET_KEY}"

echo "checking netbox-seed-hook-absent (bmaas-ci infra deploys none)"
netbox_seed_check osac-infra "${INFRA_CHART_DIR}" \
  --values "${INSTALLER_DIR}/values/bmaas-ci/infra.yaml" \
  --set osacNamespace=osac
[ "${NETBOX_TOKEN_SEEDED}" = "0" ] \
  || fail "netbox-seed-hook-absent: bmaas-ci infra unexpectedly seeds the token"

# The bridge: only the specific lookup failure above is retried with the
# placeholder, and only for a seeded install whose seed-hook Secret
# identity matches what the osac chart reads, so the profile renders like
# the gate does. The render runs in the osac namespace like the gate's
# own --namespace $(NS).
echo "checking netbox-profile-gate-placeholder (bridged render)"
netbox_seed_check osac-infra "${INFRA_CHART_DIR}" \
  --values "${INSTALLER_DIR}/values/bmaas-ci/infra.yaml" \
  --values "${INSTALLER_DIR}/values/bmaas-netbox-ci/infra.yaml" \
  --set osacNamespace=osac
render_osac_chart_offline offline-validation-placeholder \
  osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
  --namespace osac \
  "${NETBOX_PROFILE_ARGS[@]}" \
  || fail "netbox-profile-gate-placeholder: the bridged render failed"

# The bridge must verify the seed hook's Secret identity: a caller override
# that diverges from the seeded Secret (here the key, via
# bmf.netbox.tokenSecretKey) would pass a bridged render yet fail the real
# install only after install-infra changed the cluster. The gate fails
# instead, naming both identities.
echo "checking netbox-key-mismatch (seeded key differs from the chart's key)"
if render_osac_chart_offline offline-validation-placeholder \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.netbox.tokenSecretKey=api-token \
    2>"${netbox_gate_err}"; then
  fail "netbox-key-mismatch: the gate bridged a mismatched Secret key"
fi
grep -q 'identity mismatch' "${netbox_gate_err}" \
  || fail "netbox-key-mismatch: the failure did not name the identity mismatch"
grep -Fq 'osac chart reads Secret netbox-api-token/api-token' "${netbox_gate_err}" \
  || fail "netbox-key-mismatch: the failure did not name the divergent key"

echo "checking netbox-name-mismatch (seeded name differs from the chart's name)"
if render_osac_chart_offline offline-validation-placeholder \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.secrets.netboxToken=other-token \
    2>"${netbox_gate_err}"; then
  fail "netbox-name-mismatch: the gate bridged a mismatched Secret name"
fi
grep -q 'identity mismatch' "${netbox_gate_err}" \
  || fail "netbox-name-mismatch: the failure did not name the identity mismatch"
grep -Fq 'osac chart reads Secret other-token/' "${netbox_gate_err}" \
  || fail "netbox-name-mismatch: the failure did not name the divergent Secret name"

# Without the seed hook nothing creates the token Secret, so the same
# lookup failure is a real input error: the bridge must not paper over it,
# or the gate would pass an install that fails only after install-infra
# changed the cluster.
echo "checking netbox-unseeded-bridge (no seed hook: the token error is real)"
if NETBOX_TOKEN_SEEDED=0 render_osac_chart_offline offline-validation-placeholder \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    "${NETBOX_PROFILE_ARGS[@]}" \
    2>"${netbox_gate_err}"; then
  fail "netbox-unseeded-bridge: the gate bridged a missing token with no seed hook"
fi
grep -Eiq 'netbox\.tokenValue is required when Secret' "${netbox_gate_err}" \
  || fail "netbox-unseeded-bridge: the failure did not name the missing token"

# A caller-supplied token must reach the gate's render, never be masked by
# the placeholder: the placeholder applies only when the merged render has
# no token at all, so a token from --set, --set-string, or a values file is
# validated itself. A numeric token fails the schema in the gate, before
# any cluster change, exactly as it would fail the install. Type-error
# wording differs across Helm versions like the minimum constraints above:
# 3.18 prints "Invalid type. Expected: string, given: integer" while 3.22
# (what CI installs) prints "got number, want string".
numeric_token_pattern='(bmf\.netbox\.tokenValue|/bmf/netbox/tokenValue).*(Invalid type|got number, want string)'
echo "checking netbox-caller-numeric-token (expected failure naming the token type)"
if render_osac_chart_offline offline-validation-placeholder \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.netbox.tokenValue=123 \
    >"${TMP_DIR}/netbox-set-numeric.out" 2>"${netbox_gate_err}"; then
  fail "netbox-caller-numeric-token: the gate accepted a numeric --set token"
fi
grep -Eiq "${numeric_token_pattern}" "${netbox_gate_err}" \
  || fail "netbox-caller-numeric-token: the failure did not name the token type"

# The same through a values file: a --set placeholder would mask a
# file-supplied token (Helm applies --set after values files), so the
# bridge must render the file's value itself.
printf 'bmf:\n  netbox:\n    tokenValue: 123\n' >"${TMP_DIR}/netbox-numeric.yaml"
echo "checking netbox-file-numeric-token (expected failure naming the token type)"
if render_osac_chart_offline offline-validation-placeholder \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    "${NETBOX_PROFILE_ARGS[@]}" \
    -f "${TMP_DIR}/netbox-numeric.yaml" \
    >"${TMP_DIR}/netbox-file-numeric.out" 2>"${netbox_gate_err}"; then
  fail "netbox-file-numeric-token: the gate accepted a numeric file token"
fi
grep -Eiq "${numeric_token_pattern}" "${netbox_gate_err}" \
  || fail "netbox-file-numeric-token: the failure did not name the token type"

# A valid file-supplied token renders unmasked (the bridge is not taken).
# The token is generated at runtime so no credential-looking literal
# lives in this suite.
file_supplied_token="file-supplied-token-$(date +%s)-$$"
printf 'bmf:\n  netbox:\n    tokenValue: %s\n' "${file_supplied_token}" \
  >"${TMP_DIR}/netbox-token.yaml"
echo "checking netbox-file-string-token (expected success)"
render_osac_chart_offline offline-validation-placeholder \
  osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
  "${NETBOX_PROFILE_ARGS[@]}" \
  -f "${TMP_DIR}/netbox-token.yaml" \
  || fail "netbox-file-string-token: a valid file-supplied token must render"

# The dry run's rendered output reaches the terminal and CI logs, so
# Secret payload values -- including a password supplied through a values
# overlay -- must be masked. The overlay's token lands in the bmf NetBox
# token Secret's stringData; the redactor masks it while the rest of the
# manifest stays readable.
echo "checking dry-run-secret-redaction (an overlay password stays out of dry-run output)"
dryrun_token="dryrun-token-$(date +%s)-$$"
printf 'bmf:\n  netbox:\n    tokenValue: %s\n' "${dryrun_token}" \
  >"${TMP_DIR}/dryrun-token.yaml"
if ! helm template dryrun-osac "${OSAC_CHART_DIR}" \
    --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    -f "${TMP_DIR}/dryrun-token.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-rendered.yaml" 2>"${netbox_gate_err}"; then
  fail "dry-run-secret-redaction: the osac chart render failed"
fi
grep -Fq "${dryrun_token}" "${TMP_DIR}/dryrun-rendered.yaml" \
  && fail "dry-run-secret-redaction: the overlay's password reached the dry-run output"
grep -q 'kind: Secret' "${TMP_DIR}/dryrun-rendered.yaml" \
  || fail "dry-run-secret-redaction: the render produced no Secret to redact"
grep -q ': <redacted>' "${TMP_DIR}/dryrun-rendered.yaml" \
  || fail "dry-run-secret-redaction: no Secret payload was masked"

echo "input validation passed"
