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
DEVSTACK_CHART_DIR="${INSTALLER_DIR}/charts/osac-devstack"
HELM_BIN=${HELM_BIN:-helm}
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 "${SCRIPT_DIR}/test-input-redaction.py"

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
# after every secret-bearing Helm override form (--set, --set-string,
# --set-json, --set-literal, separated or equals-sign) redacted, so a
# secret-bearing override passed through EXTRA_HELM_ARGS cannot land in
# the log. Assertions only match command names and flag spellings, never
# the redacted values.
write_stub mock-log <<'STUB'
#!/usr/bin/env bash
set -eu
name=$1
shift
redacted=()
prev=
for arg in "$@"; do
  case "${prev}" in
    --set|--set-string|--set-json|--set-literal) arg='<redacted>' ;;
  esac
  case "${arg}" in
    --set=*|--set-string=*|--set-json=*|--set-literal=*) arg='--set=<redacted>' ;;
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

# The AAP license and the remote API address are static OSAC-install
# inputs: their checks must precede the first cluster mutation in every
# entry point that installs OSAC, including the composed `make install`
# (infra first), while install-infra alone must not require a license.
assert_static_inputs_first() {
  local target=$1
  shift
  local plan="${TMP_DIR}/${target//\//_}-static.plan"
  MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
    make -C "${SANDBOX}" --no-print-directory -n "${target}" "$@" \
    >"${plan}" 2>"${TMP_DIR}/static-plan.err" \
    || fail "make -n ${target} $* failed"
  local license_line address_line first_mutation
  license_line=$(grep -n 'AAP_LICENSE_FILE is required' "${plan}" | head -1 | cut -d: -f1)
  address_line=$(grep -n 'REMOTE_API_ADDRESS must use https' "${plan}" | head -1 | cut -d: -f1)
  first_mutation=$(grep -nE "${mutation_commands}" "${plan}" | head -1 | cut -d: -f1)
  [ -n "${license_line}" ] \
    || fail "${target} ($*): no license check in the plan"
  if [ -n "${first_mutation}" ] && [ "${license_line}" -gt "${first_mutation}" ]; then
    fail "${target} ($*): the license check follows a cluster mutation"
  fi
  if [ -n "${address_line}" ] && [ -n "${first_mutation}" ] \
    && [ "${address_line}" -gt "${first_mutation}" ]; then
    fail "${target} ($*): the remote address check follows a cluster mutation"
  fi
}

assert_static_inputs_first install PLATFORM=openshift PROFILE=dev NS=osac
assert_static_inputs_first install-osac PLATFORM=openshift PROFILE=dev NS=osac

# install-infra alone must not require the license: the check belongs to
# the OSAC install only.
infra_static_plan="${TMP_DIR}/infra-static.plan"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory -n install-infra \
  PLATFORM=openshift PROFILE=dev NS=osac \
  >"${infra_static_plan}" 2>/dev/null \
  || fail "infra-static: the install-infra plan failed"
grep -q 'AAP_LICENSE_FILE' "${infra_static_plan}" \
  && fail "infra-static: install-infra requires the AAP license"

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
# The values list reaches recipes through the environment, so the plan
# shows the $${INFRA_VALUES_EXTRA} token; the exported value itself (the
# vmaas-ci base plus the multicluster overlay) is asserted from the make
# database, proving the gate's osac-infra render applies the overlay.
sed -n '1,/prepare-remote-cluster/p' "${mc_plan}" | join_continuations \
  | grep 'helm template osac-infra' | grep -Fq '${INFRA_VALUES_EXTRA}' \
  || fail "install-multicluster: the gate render omits the values-list token"
mc_db="${TMP_DIR}/multicluster.db"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory -p -n install-multicluster \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    >"${mc_db}" 2>/dev/null || fail "make -p -n install-multicluster failed"
grep -q '^INFRA_VALUES_EXTRA := .*multicluster-infra.yaml' "${mc_db}" \
  || fail "install-multicluster: the exported values list lacks the overlay"

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

# NS is frozen verbatim before it is exported, so a Make expression in a
# caller value must not expand at parse time -- before the gate can reject
# the value. The sentinel file proves no $(shell ...) side effect ran, and
# the gate must reject the raw expression as an invalid namespace.
echo "checking ns-injection-make (Make expressions in NS stay data)"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
  PLATFORM=kind PROFILE=dev "NS=osac\$(shell touch ${ns_sentinel}-make)" \
  >"${TMP_DIR}/nsmake.out" 2>"${TMP_DIR}/nsmake.err"; then
  fail "ns-injection-make: the gate accepted a Make-expression-bearing NS"
fi
[ ! -e "${ns_sentinel}-make" ] \
  || fail "ns-injection-make: a Make expression in NS executed"
grep -q 'NS must be a lowercase DNS label' "${TMP_DIR}/nsmake.err" \
  || fail "ns-injection-make: the failure did not name the namespace rule"
assert_prevalidation_commands ns-injection-make

# The NS freeze sits outside the parse-time MAKECMDGOALS gate: make
# auto-exports command-line variables by expanding them, so a goal the
# gate does not cover (install-dry-run) would otherwise run a Make
# expression in an unvalidated NS at recipe-launch time. The sentinel
# proves the expression never executed and the gate rejected the raw
# value instead, before any render ran.
echo "checking ns-injection-ungated (goals outside the parse-time gate)"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install-dry-run \
  PLATFORM=kind PROFILE=dev "NS=osac\$(shell touch ${ns_sentinel}-ungated)" \
  >"${TMP_DIR}/nsung.out" 2>"${TMP_DIR}/nsung.err"; then
  fail "ns-injection-ungated: the gate accepted a Make-expression-bearing NS"
fi
[ ! -e "${ns_sentinel}-ungated" ] \
  || fail "ns-injection-ungated: a Make expression in NS executed"
grep -q 'NS must be a lowercase DNS label' "${TMP_DIR}/nsung.err" \
  || fail "ns-injection-ungated: the failure did not name the namespace rule"
assert_prevalidation_commands ns-injection-ungated

# Kubeconfig paths are caller-supplied data too: REMOTE_KUBECONFIG is
# frozen verbatim before the parse-time remote conditionals and
# REMOTE_CLUSTER_HELM_ARGS expand, and KUBECONFIG is frozen under an origin
# guard before the kind-file default expands it. Both reach recipes through
# the exported environment. The sentinel files prove no $(shell ...) side
# effect ran at parse or export time; the values stay valid inputs.
echo "checking kubeconfig-injection-make (Make expressions in kubeconfigs stay data)"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
  PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
  "KUBECONFIG=/tmp/hub-$(date +%s)-$$\$(shell touch ${ns_sentinel}-kubeconfig)" \
  "REMOTE_KUBECONFIG=/tmp/remote-$(date +%s)-$$\$(shell touch ${ns_sentinel}-remote-kubeconfig)" \
  >"${TMP_DIR}/kubeconfig.out" 2>"${TMP_DIR}/kubeconfig.err"; then
  :
else
  fail "kubeconfig-injection-make: the gate rejected valid kubeconfig paths"
fi
[ ! -e "${ns_sentinel}-kubeconfig" ] \
  || fail "kubeconfig-injection-make: a Make expression in KUBECONFIG executed"
[ ! -e "${ns_sentinel}-remote-kubeconfig" ] \
  || fail "kubeconfig-injection-make: a Make expression in REMOTE_KUBECONFIG executed"
grep -q 'Installer input validation passed' "${TMP_DIR}/kubeconfig.out" \
  || fail "kubeconfig-injection-make: the gate did not complete"
assert_prevalidation_commands kubeconfig-injection-make

# An empty caller KUBECONFIG is not a path: the Makefile must fall back to
# the kind kubeconfig so helm never silently uses the home kubeconfig. The
# frozen value has origin "override", so the fallback assignment must be an
# override too; a plain assignment would leave the value empty.
echo "checking kubeconfig-empty-fallback (an empty KUBECONFIG uses the kind file)"
if ! KUBECONFIG= make -C "${SANDBOX}" --no-print-directory \
    --eval='print-kubeconfig: ; @echo $(KUBECONFIG)' \
    print-kubeconfig PLATFORM=kind PROFILE=dev NS=osac \
    >"${TMP_DIR}/kubeconfig-empty.out" 2>"${TMP_DIR}/kubeconfig-empty.err"; then
  fail "kubeconfig-empty-fallback: make rejected an empty KUBECONFIG"
fi
grep -q -- '-kind\.kubeconfig$' "${TMP_DIR}/kubeconfig-empty.out" \
  || fail "kubeconfig-empty-fallback: an empty KUBECONFIG did not use the kind file"

# Caller-supplied Helm args are data, never command text: EXTRA_HELM_ARGS
# is frozen verbatim (no Make expression in it expands, including at
# export time) and reaches recipes through the environment, so both Make
# syntax and shell metacharacters in a caller value must reach Helm as
# argument text instead of executing. The sentinel files prove nothing ran.
echo "checking extra-args-injection (metacharacters in EXTRA_HELM_ARGS stay data)"
extra_sentinel="${TMP_DIR}/extra-args-injection-ran"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    EXTRA_HELM_ARGS='--set operator.fulfillment.serverAddress=ok$(touch '"${extra_sentinel}"')-$$(touch '"${extra_sentinel}"'-2)' \
    >"${TMP_DIR}/extra-args.out" 2>"${TMP_DIR}/extra-args.err"; then
  :
else
  fail "extra-args-injection: the gate rejected a valid EXTRA_HELM_ARGS value"
fi
[ ! -e "${extra_sentinel}" ] \
  || fail "extra-args-injection: Make syntax in EXTRA_HELM_ARGS executed"
[ ! -e "${extra_sentinel}-2" ] \
  || fail "extra-args-injection: shell metacharacters in EXTRA_HELM_ARGS executed"
grep -q 'helm template osac ' "${LOG}" \
  || fail "extra-args-injection: the gate render never ran"
assert_prevalidation_commands extra-args-injection

# Caller-supplied values lists are data too: INFRA_VALUES_EXTRA is frozen
# and env-passed, so shell metacharacters in it word-split into Helm
# argument text (visible in the stub log) instead of executing.
echo "checking infra-values-injection (metacharacters in INFRA_VALUES_EXTRA stay data)"
infra_sentinel="${TMP_DIR}/infra-values-injection-ran"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
    PLATFORM=openshift PROFILE=dev NS=osac \
    "INFRA_VALUES_EXTRA=-f values/dev/infra.yaml; touch ${infra_sentinel}" \
    >"${TMP_DIR}/infra-args.out" 2>"${TMP_DIR}/infra-args.err"; then
  :
else
  fail "infra-values-injection: the gate rejected a valid INFRA_VALUES_EXTRA value"
fi
[ ! -e "${infra_sentinel}" ] \
  || fail "infra-values-injection: shell metacharacters in INFRA_VALUES_EXTRA executed"
grep -q -- '-f values/dev/infra.yaml; touch' "${LOG}" \
  || fail "infra-values-injection: the metacharacter-bearing list did not reach Helm as data"
assert_prevalidation_commands infra-values-injection

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

# The dry run's helm commands are not echoed by make: recipe text can
# carry an inline --set password through EXTRA_HELM_ARGS, and make's echo
# of a recipe line would print it to the terminal and CI logs before any
# redacted render runs. The password reaches Helm through the environment
# (the stub log redacts --set values), so neither make's output nor a
# leaked env token may expose it.
echo "checking dry-run-echo-suppression (inline passwords stay out of make's echo)"
echo_password="inline-password-$(date +%s)-$$"
: >"${LOG}"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install-dry-run \
    PLATFORM=kind PROFILE=dev NS=osac \
    "EXTRA_HELM_ARGS=--set=bmf.netbox.tokenValue=${echo_password}" \
    >"${TMP_DIR}/dryrun-echo.out" 2>"${TMP_DIR}/dryrun-echo.err" \
  || fail "dry-run-echo-suppression: the stubbed dry run failed"
grep -Fq "${echo_password}" "${TMP_DIR}/dryrun-echo.out" "${TMP_DIR}/dryrun-echo.err" \
  && fail "dry-run-echo-suppression: make echoed an inline password"
grep -Fq '${EXTRA_HELM_ARGS}' "${TMP_DIR}/dryrun-echo.out" \
  && fail "dry-run-echo-suppression: a raw env token reached the output"
grep -q 'helm template osac ' "${LOG}" \
  || fail "dry-run-echo-suppression: the dry run never rendered the osac chart"

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

# The AAP license is a static input to the OSAC install only: `make
# install` composes install-infra before install-osac, so a missing
# license must be rejected before install-infra creates namespaces and
# waits for readiness.
echo "checking license-before-infra (a missing license fails before install-infra)"
: >"${LOG}"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install \
    PLATFORM=openshift PROFILE=dev NS=osac \
    AAP_LICENSE_FILE="${TMP_DIR}/missing-license.zip" \
    >"${TMP_DIR}/license-missing.out" 2>"${TMP_DIR}/license-missing.err"; then
  fail "license-before-infra: make install succeeded with a missing license"
fi
grep -q 'AAP_LICENSE_FILE not found' "${TMP_DIR}/license-missing.err" \
  || fail "license-before-infra: the failure did not name the license"
if grep -Eq "${mutation_commands}" "${LOG}"; then
  fail "license-before-infra: a cluster mutation ran before the license check"
fi

# The remote API address is static too: a non-https value must fail in
# validate-osac-inputs, before install-osac creates the namespace (the
# kubeconfig readability and Secret staging stay at install time).
echo "checking remote-address-scheme (a non-https remote address fails before mutations)"
: >"${LOG}"
: >"${TMP_DIR}/license.zip"
if MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  make -C "${SANDBOX}" --no-print-directory install-osac \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    AAP_LICENSE_FILE="${TMP_DIR}/license.zip" \
    REMOTE_KUBECONFIG="${LOG}" \
    REMOTE_API_ADDRESS="http://insecure.internal.example.com" \
    >"${TMP_DIR}/addr-bad.out" 2>"${TMP_DIR}/addr-bad.err"; then
  fail "remote-address-scheme: install-osac succeeded with a non-https address"
fi
grep -q 'REMOTE_API_ADDRESS must use https' "${TMP_DIR}/addr-bad.err" \
  || fail "remote-address-scheme: the failure did not name the address rule"
if grep -Eq "${mutation_commands}" "${LOG}"; then
  fail "remote-address-scheme: a cluster mutation ran before the address check"
fi
assert_prevalidation_commands remote-address-scheme

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
    | grep -Eq '\$\{EXTRA_HELM_ARGS\}.*operator\.remoteClusterKubeconfigSecretName=osac-remote-kubeconfig' \
    || fail "remote-flag order: ${remote_cmd} does not apply EXTRA_HELM_ARGS before the remote-cluster flags"
done
# The caller-supplied override itself must flow to Helm at runtime: with
# stubbed Helm the gate succeeds and the render runs with the args in the
# environment (mock-log redacts --set-string values, so only the run is
# asserted here; the wiring above pins where the token is applied).
: >"${LOG}"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    EXTRA_HELM_ARGS='--set-string operator.remoteClusterKubeconfigSecretName=caller-override' \
    >"${TMP_DIR}/remote-order.out" 2>"${TMP_DIR}/remote-order.err" \
    || fail "remote-flag order: the gate rejected a valid EXTRA_HELM_ARGS override"
grep -q 'helm template osac ' "${LOG}" \
  || fail "remote-flag order: the gate render never ran with the override"

# Every secret-bearing Helm override form must stay out of the stub log
# when the args are inherited through make's environment: a caller can
# pass a password via --set-json or --set-literal (separated or
# equals-sign form) just as easily as via --set.
echo "checking stub-set-redaction (all override forms stay out of the log)"
stub_secret="stub-secret-$(date +%s)-$$"
: >"${LOG}"
MOCK_LOG="${LOG}" PATH="${STUB_BIN}:${PATH}" \
  REMOTE_KUBECONFIG="${LOG}" \
  make -C "${SANDBOX}" --no-print-directory validate-inputs \
    PLATFORM=openshift PROFILE=vmaas-ci NS=osac \
    EXTRA_HELM_ARGS="--set-json global.example={\"pw\":\"${stub_secret}\"} --set-json=global.other={\"pw\":\"${stub_secret}\"} --set-literal bmf.netbox.tokenValue=${stub_secret} --set-literal=bmf.netbox.tokenValue=${stub_secret}" \
    >"${TMP_DIR}/stub-set.out" 2>"${TMP_DIR}/stub-set.err" \
    || fail "stub-set-redaction: the gate rejected a valid EXTRA_HELM_ARGS override"
grep -Fq "${stub_secret}" "${LOG}" \
  && fail "stub-set-redaction: a secret-bearing override reached the stub log"
stub_eq_forms=$(grep -o -- '--set=<redacted>' "${LOG}" | wc -l)
[ "${stub_eq_forms}" -ge 2 ] \
  || fail "stub-set-redaction: an equals-sign form was not redacted (${stub_eq_forms}/2)"
grep -q -- '--set-literal <redacted>' "${LOG}" \
  || fail "stub-set-redaction: the separated --set-literal form was not redacted"
grep -q -- '--set-json <redacted>' "${LOG}" \
  || fail "stub-set-redaction: the separated --set-json form was not redacted"

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
# The seed-check render must apply the same cluster-specific overrides as
# the gate's own osac-infra render (and install-infra's upgrade): an
# overlay value the install overrides on the command line -- for example
# an empty bundledVault.keycloakIssuerUrl filled in with the cluster
# domain -- must not fail the seed check alone, which would silently
# disable the token bridge and reject a valid seeded install with a
# misleading missing-token error. Make expands the cluster lookups into
# the printed recipe (the stubbed oc answers 4.22.14 and
# apps.example.com), so the expected values are the expanded ones.
for seed_override in \
  '--set lvms.channel=stable-4.22' \
  '--set keycloak.hostname=https://keycloak-keycloak.apps.example.com' \
  '--set keycloak.route.hostname=keycloak-keycloak.apps.example.com' \
  '--set keycloak.uiUrl=https://osac-ui-osac.apps.example.com' \
  '--set "bundledVault.keycloakIssuerUrl=https://keycloak-keycloak.apps.example.com/realms/osac"'; do
  join_continuations <"${remote_plan}" | grep 'netbox_seed_check osac-infra' \
    | grep -Fq -- "${seed_override}" \
    || fail "validate-inputs: the seed-check render omits ${seed_override}"
done

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
  echo "checking ${name} (expected failure matching '${pattern}')"
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
  echo "checking ${name} (expected failure matching '${pattern}')"
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

# runAsUser 0 with the default runAsNonRoot true only fails at
# provisioning -- the kubelet refuses to start a root container flagged
# non-root -- so the schema rejects the combination up front. UID 0
# stays allowed when runAsNonRoot is explicitly false. The `not` keyword
# wording differs by Helm version: 3.18 prints "Must not validate the
# schema (not)" with the dotted path while 3.22 (what CI installs)
# prints "'not' failed" with a JSON-pointer path; the pattern accepts
# both, in the dotted-path (Helm 3) and JSON-pointer (newer) spellings.
render_infra_failure_matching \
  vault-runasuser-zero-nonroot \
  '(bundledVault\.podSecurityContext|/bundledVault/podSecurityContext).*(not validate|not. failed)' \
  --set bundledVault.podSecurityContext.runAsUser=0

render_infra_success \
  vault-runasuser-zero-root \
  --set bundledVault.podSecurityContext.runAsUser=0 \
  --set bundledVault.podSecurityContext.runAsNonRoot=false

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
# (NETBOX_OFFLINE_PLACEHOLDER in the Makefile, generated at runtime there;
# the plan assertion above matches only its prefix) that is never passed to
# an installation -- and only when
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
# The render-only placeholder mirrors the Makefile's runtime-generated
# NETBOX_OFFLINE_PLACEHOLDER; only its prefix is asserted against the
# gate's plan above, so the two values need not match. Generated here so
# no token-shaped literal sits in the script.
offline_token="offline-validation-placeholder-$(date +%s)-$$"

# The unseeded bridge path (a pre-existing token Secret) is tested
# hermetically: stub CLIs stand in for the cluster lookup, so no developer
# cluster or login state can flip the result. The kubectl stub logs every
# invocation and answers "present" only for the exact Secret identity and
# key the lookup asks for; the oc stub never answers, so the kubectl path
# is what runs (lib.sh falls back to oc only when kubectl is unavailable).
netbox_cli_bin="${TMP_DIR}/netbox-cli"
mkdir -p "${netbox_cli_bin}"
netbox_cli_log="${TMP_DIR}/netbox-cli.log"
cat >"${netbox_cli_bin}/kubectl" <<'STUB'
#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >>"${NETBOX_CLI_LOG}"
[ "${NETBOX_CLI_SECRET_PRESENT:-0}" = "1" ] || exit 0
[ "$1 $2 $3 $4 $5" = "get secret ${NETBOX_CLI_NAME} -n ${NETBOX_CLI_NS}" ] || exit 0
for arg in "$@"; do
  case "${arg}" in
    *"index .data \"${NETBOX_CLI_KEY}\""*) echo present; exit 0 ;;
  esac
done
exit 0
STUB
cat >"${netbox_cli_bin}/oc" <<'STUB'
#!/usr/bin/env bash
printf 'oc %s\n' "$*" >>"${NETBOX_CLI_LOG}"
exit 1
STUB
chmod +x "${netbox_cli_bin}/kubectl" "${netbox_cli_bin}/oc"

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
render_osac_chart_offline "${offline_token}" \
  osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
  --namespace osac \
  "${NETBOX_PROFILE_ARGS[@]}" \
  || fail "netbox-profile-gate-placeholder: the bridged render failed"

# The bridge must verify the seed hook's Secret identity: a caller override
# that diverges from the seeded Secret (here the key, via
# bmf.netbox.tokenSecretKey) would pass a bridged render yet fail the real
# install only after install-infra changed the cluster. The gate fails
# instead, naming the differing identity fields. The mismatching values
# are internal-hostname-shaped on purpose: Secret names and keys are
# customer-supplied identifiers, and the gate's errors reach the terminal
# and CI logs, so the values themselves must stay out of the message.
echo "checking netbox-key-mismatch (seeded key differs from the chart's key)"
if render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.netbox.tokenSecretKey=token.netbox.internal.example.com \
    2>"${netbox_gate_err}"; then
  fail "netbox-key-mismatch: the gate bridged a mismatched Secret key"
fi
grep -q 'identity mismatch' "${netbox_gate_err}" \
  || fail "netbox-key-mismatch: the failure did not name the identity mismatch"
grep -Fq 'differing: key' "${netbox_gate_err}" \
  || fail "netbox-key-mismatch: the failure did not name the differing field"
grep -Fq 'token.netbox.internal.example.com' "${netbox_gate_err}" \
  && fail "netbox-key-mismatch: the failure echoed the divergent key"

echo "checking netbox-name-mismatch (seeded name differs from the chart's name)"
if render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.secrets.netboxToken=netbox.internal.example.com \
    2>"${netbox_gate_err}"; then
  fail "netbox-name-mismatch: the gate bridged a mismatched Secret name"
fi
grep -q 'identity mismatch' "${netbox_gate_err}" \
  || fail "netbox-name-mismatch: the failure did not name the identity mismatch"
grep -Fq 'differing: name' "${netbox_gate_err}" \
  || fail "netbox-name-mismatch: the failure did not name the differing field"
grep -Fq 'netbox.internal.example.com' "${netbox_gate_err}" \
  && fail "netbox-name-mismatch: the failure echoed the divergent Secret name"

# Without the seed hook nothing creates the token Secret, so the same
# lookup failure is a real input error unless the Secret already exists in
# the cluster: the bridge must not paper over a genuinely missing token,
# or the gate would pass an install that fails only after install-infra
# changed the cluster. The stub CLIs answer nothing here (no Secret). The
# gate names the constraint without the chart's raw error, which embeds
# the customer-supplied Secret name and key.
echo "checking netbox-unseeded-bridge (no seed hook and no Secret: the token error is real)"
if PATH="${netbox_cli_bin}:${PATH}" NETBOX_CLI_LOG="${netbox_cli_log}" \
    NETBOX_TOKEN_SEEDED=0 render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.secrets.netboxToken=netbox.internal.example.com \
    2>"${netbox_gate_err}"; then
  fail "netbox-unseeded-bridge: the gate bridged a missing token with no seed hook"
fi
grep -Eiq 'netbox\.tokenValue is required when the NetBox token Secret' \
  "${netbox_gate_err}" \
  || fail "netbox-unseeded-bridge: the failure did not name the missing token"
grep -Fq 'netbox.internal.example.com' "${netbox_gate_err}" \
  && fail "netbox-unseeded-bridge: the failure echoed the Secret name"

# A token Secret that already exists in the cluster is the other
# legitimate unseeded source: `helm upgrade` reads it through lookup at
# install time even though `helm template` cannot see it offline, so the
# gate verifies it with a read-only cluster lookup instead of rejecting a
# valid install. The stub answers only for the exact identity the chart
# renders (netbox-api-token in osac, key token), proving the lookup uses
# the effective values, and the log proves it is read-only.
echo "checking netbox-existing-secret (a pre-existing token Secret passes the gate)"
: >"${netbox_cli_log}"
if ! PATH="${netbox_cli_bin}:${PATH}" NETBOX_CLI_LOG="${netbox_cli_log}" \
    NETBOX_CLI_SECRET_PRESENT=1 NETBOX_CLI_NAME=netbox-api-token \
    NETBOX_CLI_NS=osac NETBOX_CLI_KEY=token NETBOX_TOKEN_SEEDED=0 \
    render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    2>"${netbox_gate_err}"; then
  fail "netbox-existing-secret: the gate rejected an install whose token Secret exists"
fi
grep -q 'kubectl get secret netbox-api-token -n osac' "${netbox_cli_log}" \
  || fail "netbox-existing-secret: the lookup did not use the rendered Secret identity"
grep -q -- '-o go-template' "${netbox_cli_log}" \
  || fail "netbox-existing-secret: the lookup was not the read-only template check"
grep -Eq 'kubectl (apply|create|delete|patch|replace|edit)' "${netbox_cli_log}" \
  && fail "netbox-existing-secret: the gate mutated the cluster"

# A Secret that exists under a different key than the chart reads is still
# a real input error: the caller overrode bmf.netbox.tokenSecretKey, so
# the lookup asks for that key and nothing answers.
echo "checking netbox-existing-secret-wrong-key (a Secret missing the chart's key fails)"
if PATH="${netbox_cli_bin}:${PATH}" NETBOX_CLI_LOG="${netbox_cli_log}" \
    NETBOX_CLI_SECRET_PRESENT=1 NETBOX_CLI_NAME=netbox-api-token \
    NETBOX_CLI_NS=osac NETBOX_CLI_KEY=token NETBOX_TOKEN_SEEDED=0 \
    render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    --set bmf.netbox.tokenSecretKey=api-token \
    2>"${netbox_gate_err}"; then
  fail "netbox-existing-secret-wrong-key: the gate bridged a Secret without the chart's key"
fi
grep -Eiq 'netbox\.tokenValue is required when the NetBox token Secret' \
  "${netbox_gate_err}" \
  || fail "netbox-existing-secret-wrong-key: the failure did not name the missing token"

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
if render_osac_chart_offline "${offline_token}" \
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
if render_osac_chart_offline "${offline_token}" \
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
render_osac_chart_offline "${offline_token}" \
  osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
  "${NETBOX_PROFILE_ARGS[@]}" \
  -f "${TMP_DIR}/netbox-token.yaml" \
  || fail "netbox-file-string-token: a valid file-supplied token must render"

# A duplicate metering reader name must fail the gate's own render (the
# umbrella chart carries the readers into the metering subchart) without
# echoing the name: reader names are customer-supplied infrastructure
# identifiers -- often internal hostnames -- and the gate's error text
# reaches the terminal and CI logs.
echo "checking metering-reader-duplicate (duplicate names fail the gate without the name)"
if render_osac_chart_offline "${offline_token}" \
    osac "${OSAC_CHART_DIR}" --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    --set 'metering.readers[0].name=metrics-reader.internal.example.com' \
    --set 'metering.readers[1].name=metrics-reader.internal.example.com' \
    >/dev/null 2>"${netbox_gate_err}"; then
  fail "metering-reader-duplicate: the gate accepted a duplicate reader name"
fi
grep -Eiq 'duplicate metering reader' "${netbox_gate_err}" \
  || fail "metering-reader-duplicate: the failure did not name the constraint"
grep -Fq 'metrics-reader.internal.example.com' "${netbox_gate_err}" \
  && fail "metering-reader-duplicate: the failure echoed the reader name"

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

# Multi-line Secret payloads must be redacted too: Helm renders a value
# containing newlines as a block scalar (`key: |`) whose body lines sit
# deeper than the entry keys. The redactor drops the body lines and masks
# the key line, so PEM-shaped credentials cannot reach the dry-run output.
echo "checking dry-run-multiline-secret-redaction (block-scalar payloads stay out)"
multiline_token="multiline-token-$(date +%s)-$$"
{
  printf 'bmf:\n  netbox:\n    tokenValue: |\n'
  printf '      header-%s\n' "${multiline_token}"
  printf '      footer-%s\n' "${multiline_token}"
} >"${TMP_DIR}/dryrun-multiline-token.yaml"
if ! helm template dryrun-osac "${OSAC_CHART_DIR}" \
    --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    -f "${TMP_DIR}/dryrun-multiline-token.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-multiline-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-multiline-secret-redaction: the osac chart render failed"
fi
grep -Fq "header-${multiline_token}" "${TMP_DIR}/dryrun-multiline-rendered.yaml" \
  && fail "dry-run-multiline-secret-redaction: a block-scalar body line survived"
grep -Fq "footer-${multiline_token}" "${TMP_DIR}/dryrun-multiline-rendered.yaml" \
  && fail "dry-run-multiline-secret-redaction: a block-scalar body line survived"
grep -q 'kind: Secret' "${TMP_DIR}/dryrun-multiline-rendered.yaml" \
  || fail "dry-run-multiline-secret-redaction: the render produced no Secret"
# Direct redactor check for the block-scalar body rule, independent of
# Helm's YAML marshaling choices for the chart's values.
printf '%s\n' 'kind: Secret' 'stringData:' '  tls.crt: |' \
  "    -----BEGIN ${multiline_token}-----" \
  | "${SCRIPT_DIR}/redact-secret-values.sh" \
  | grep -Fq -- "-----BEGIN ${multiline_token}-----" \
  && fail "dry-run-multiline-secret-redaction: the redactor kept a block-scalar body"
# A Secret payload entry keyed `name` must be masked like any other
# payload value, not mistaken for the document's metadata name.
printf '%s\n' 'kind: Secret' 'metadata:' '  name: tls' 'stringData:' \
  "  name: ${multiline_token}-name-key" \
  | "${SCRIPT_DIR}/redact-secret-values.sh" \
  | grep -Fq -- "${multiline_token}-name-key" \
  && fail "dry-run-multiline-secret-redaction: a payload entry named name leaked"

# The EVPN/Netris overlay carries internal infrastructure hostnames into
# the AAP instance-group ConfigMaps (`*-ig`); the dry run must mask that
# endpoint config so internal hostnames (and any credential misplaced in
# the config half instead of the parallel Secret) stay out of CI logs.
echo "checking dry-run-evpn-endpoint-redaction (internal hostnames stay out)"
evpn_host="netris-ctrl-$(date +%s)-$$.lab.internal.example.com"
if ! helm template dryrun-osac "${OSAC_CHART_DIR}" \
    --values "${INSTALLER_DIR}/values/vmaas-ci/instance.yaml" \
    --values "${INSTALLER_DIR}/values/vmaas-ci/netris.yaml" \
    --namespace osac \
    --set service.externalHostname=fulfillment-api-osac.apps.example.com \
    --set service.internalHostname=fulfillment-internal-api-osac.apps.example.com \
    --set ui.auth.oidcIssuerURL=https://keycloak-keycloak.apps.example.com/realms/osac \
    --set "aap.instanceGroups.networkFulfillment.config.NETRIS_CONTROLLER_URL=https://${evpn_host}" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-evpn-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-evpn-endpoint-redaction: the osac chart render failed"
fi
grep -Fq "${evpn_host}" "${TMP_DIR}/dryrun-evpn-rendered.yaml" \
  && fail "dry-run-evpn-endpoint-redaction: an internal hostname reached the dry-run output"
grep -q 'kind: ConfigMap' "${TMP_DIR}/dryrun-evpn-rendered.yaml" \
  || fail "dry-run-evpn-endpoint-redaction: the render produced no ConfigMap"
grep -q 'NETRIS_CONTROLLER_URL: <redacted>' "${TMP_DIR}/dryrun-evpn-rendered.yaml" \
  || fail "dry-run-evpn-endpoint-redaction: the endpoint config was not masked"

# The EVPN fabric config (the osac-infra-evpn-config ConfigMap) carries
# internal node hostnames and fabric peer addresses from the infra
# overlay; the dry run must mask that data too, while the ConfigMap and
# its entry keys stay visible for review.
echo "checking dry-run-evpn-fabric-redaction (infra node hostnames stay out)"
evpn_node="lab-worker-$(date +%s)-$$.internal.example.com"
cat >"${TMP_DIR}/dryrun-evpn-fabric.yaml" <<EVPN_EOF
evpn:
  enabled: true
  vtepCIDR: 10.200.255.0/24
  bgp:
    asn: 4209999999
    acceptPrefixes:
      - 10.200.255.0/24
  nodes:
    - name: ${evpn_node}
      vtepIP: 10.200.255.1
      uplinks:
        - interface: ens6
          peerAddress: 169.254.133.1
          peerASN: 4200300002
EVPN_EOF
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-evpn-fabric.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-evpn-fabric-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-evpn-fabric-redaction: the osac-infra chart render failed"
fi
grep -Fq "${evpn_node}" "${TMP_DIR}/dryrun-evpn-fabric-rendered.yaml" \
  && fail "dry-run-evpn-fabric-redaction: an internal node hostname reached the dry-run output"
grep -Fq '169.254.133.1' "${TMP_DIR}/dryrun-evpn-fabric-rendered.yaml" \
  && fail "dry-run-evpn-fabric-redaction: a fabric peer address reached the dry-run output"
grep -q 'name: osac-infra-evpn-config' "${TMP_DIR}/dryrun-evpn-fabric-rendered.yaml" \
  || fail "dry-run-evpn-fabric-redaction: the EVPN config ConfigMap is missing"
grep -q 'nodes.txt: <redacted>' "${TMP_DIR}/dryrun-evpn-fabric-rendered.yaml" \
  || fail "dry-run-evpn-fabric-redaction: the node list was not masked"

# A values overlay can render a ConfigMap through the NetBox chart's
# extraDeploy; a credential-shaped data key there is plain text in the
# dry-run output like an env value, and a block-scalar body (a multi-line
# token or PEM) must be dropped with the key. The plain entry stays
# readable so the rendered configuration remains reviewable.
echo "checking dry-run-configmap-credential-redaction (overlay ConfigMap secrets stay out)"
cm_token="configmap-token-$(date +%s)-$$"
cm_password="configmap-password-$(date +%s)-$$"
cat >"${TMP_DIR}/dryrun-configmap-credential.yaml" <<CM_EOF
netbox:
  extraDeploy:
    - apiVersion: v1
      kind: ConfigMap
      metadata:
        name: netbox-integration
      data:
        apiToken: |
          ${cm_token}
        adminPassword: ${cm_password}
        plainValue: readable
CM_EOF
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/bmaas-ci/infra.yaml" \
    --values "${INSTALLER_DIR}/values/bmaas-netbox-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-configmap-credential.yaml" \
    --set osacNamespace=osac \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-configmap-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-configmap-credential-redaction: the osac-infra render failed"
fi
grep -Fq "${cm_token}" "${TMP_DIR}/dryrun-configmap-rendered.yaml" \
  && fail "dry-run-configmap-credential-redaction: a block-scalar ConfigMap token survived"
grep -Fq "${cm_password}" "${TMP_DIR}/dryrun-configmap-rendered.yaml" \
  && fail "dry-run-configmap-credential-redaction: a ConfigMap password survived"
grep -q 'name: netbox-integration' "${TMP_DIR}/dryrun-configmap-rendered.yaml" \
  || fail "dry-run-configmap-credential-redaction: the overlay ConfigMap is missing"
grep -q 'apiToken: <redacted>' "${TMP_DIR}/dryrun-configmap-rendered.yaml" \
  || fail "dry-run-configmap-credential-redaction: the ConfigMap token was not masked"
grep -q 'plainValue: readable' "${TMP_DIR}/dryrun-configmap-rendered.yaml" \
  || fail "dry-run-configmap-credential-redaction: the non-credential entry was masked"

# A ConfigMap data value can also be a whole configuration file: a
# block-scalar key like netbox.conf says nothing about credentials, but
# its body may carry a password assignment. The dry run prints that body,
# so the redactor masks credential assignments in place and leaves the
# rest of the file readable. This path goes through make and
# INFRA_VALUES_EXTRA, the way an operator supplies an overlay. It runs
# against this checkout, not the sandbox: earlier stubbed dry runs cleared
# the sandbox's built chart dependencies, and every dependency recipe is
# skipped here with -o so this run writes nothing.
echo "checking dry-run-configmap-file-redaction (file payloads from INFRA_VALUES_EXTRA stay out)"
cm_file_password="configmap-file-password-$(date +%s)-$$"
cm_file_token="configmap-file-token-$(date +%s)-$$"
cm_file_key="configmap-file-key-$(date +%s)-$$"
cm_file_auth="configmap-file-auth-$(date +%s)-$$"
cat >"${TMP_DIR}/dryrun-configmap-file.yaml" <<CM_FILE_EOF
netbox:
  extraDeploy:
    - apiVersion: v1
      kind: ConfigMap
      metadata:
        name: netbox-file-config
      data:
        netbox.conf: |
          [database]
          host = netbox-db
          password = ${cm_file_password}
          token = ${cm_file_token}
          export DB_PASSWORD=${cm_file_password}
          - token: ${cm_file_token}
          encryption_key: ${cm_file_key}
          export SIGNING_KEY=${cm_file_key}
          Authorization: Bearer ${cm_file_auth}
          author = readable
CM_FILE_EOF
if ! make -C "${INSTALLER_DIR}" --no-print-directory \
    -o helm-deps -o helm-infra-deps -o helm-osac-deps \
    -o validate-osac-chart-oci-ref install-dry-run \
    PLATFORM=openshift PROFILE=bmaas-netbox-ci NS=osac \
    DRY_RUN_OCP_VERSION=4.22 DRY_RUN_CLUSTER_DOMAIN=apps.example.com \
    "INFRA_VALUES_EXTRA=-f values/bmaas-netbox-ci/infra.yaml -f ${TMP_DIR}/dryrun-configmap-file.yaml" \
    EXTRA_HELM_ARGS=--set=bmf.netbox.tokenValue=offline-placeholder \
    >"${TMP_DIR}/dryrun-configmap-file.out" \
    2>"${TMP_DIR}/dryrun-configmap-file.err"; then
  fail "dry-run-configmap-file-redaction: the dry run failed"
fi
grep -Fq "${cm_file_password}" "${TMP_DIR}/dryrun-configmap-file.out" \
  && fail "dry-run-configmap-file-redaction: a file payload password survived"
grep -Fq "${cm_file_token}" "${TMP_DIR}/dryrun-configmap-file.out" \
  && fail "dry-run-configmap-file-redaction: a file payload token survived"
grep -Fq "${cm_file_key}" "${TMP_DIR}/dryrun-configmap-file.out" \
  && fail "dry-run-configmap-file-redaction: a KEY-suffixed value survived"
grep -Fq "${cm_file_auth}" "${TMP_DIR}/dryrun-configmap-file.out" \
  && fail "dry-run-configmap-file-redaction: an Authorization value survived"
grep -q 'name: netbox-file-config' "${TMP_DIR}/dryrun-configmap-file.out" \
  || fail "dry-run-configmap-file-redaction: the overlay ConfigMap is missing"
grep -q 'password = <redacted>' "${TMP_DIR}/dryrun-configmap-file.out" \
  || fail "dry-run-configmap-file-redaction: the file password was not masked"
grep -q 'export DB_PASSWORD=<redacted>' "${TMP_DIR}/dryrun-configmap-file.out" \
  || fail "dry-run-configmap-file-redaction: a prefixed assignment was not masked"
grep -q 'Authorization: <redacted>' "${TMP_DIR}/dryrun-configmap-file.out" \
  || fail "dry-run-configmap-file-redaction: an Authorization header was not masked"
grep -q 'author = readable' "${TMP_DIR}/dryrun-configmap-file.out" \
  || fail "dry-run-configmap-file-redaction: a non-credential line was masked"

# Container env entries are a plain-text channel for credentials: callers
# can inject passwords into workload specs through values overlays (for
# example keycloak.extraEnv) instead of Secret references. The chart
# routes extraEnv values through the keycloak-extra-env Secret and
# references them with secretKeyRef, so they never render as plain-text
# env values -- whatever the variable is named -- and the redactor masks
# them as a Secret payload. Env values elsewhere whose variable name is
# credential-shaped are masked in place, while ordinary configuration
# env values stay readable for review.
echo "checking dry-run-env-redaction (overlay env passwords stay out)"
env_password="env-password-$(date +%s)-$$"
env_session="env-session-$(date +%s)-$$"
env_apikey="env-apikey-$(date +%s)-$$"
env_signkey="env-signkey-$(date +%s)-$$"
env_dsn="env-dsn-$(date +%s)-$$"
cat >"${TMP_DIR}/dryrun-env-token.yaml" <<ENV_EOF
keycloak:
  extraEnv:
    # Benignly named entries on purpose: the values must stay out of the
    # dry-run output regardless of the variable name they travel under.
    - name: KC_SPI_DEMO_URL
      value: ${env_password}
    - name: KC_SPI_DEMO_SESSION
      value: ${env_session}
    - name: KC_SPI_DEMO_CLIENT
      value: ${env_apikey}
    - name: KC_SPI_DEMO_SIGNING_KEY
      value: ${env_signkey}
    - name: KC_SPI_DEMO_DATABASE_DSN
      value: ${env_dsn}
ENV_EOF
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-env-token.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-env-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-env-redaction: the osac-infra chart render failed"
fi
for leaked in "${env_password}" "${env_session}" "${env_apikey}" \
  "${env_signkey}" "${env_dsn}"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-env-rendered.yaml" \
    && fail "dry-run-env-redaction: an overlay env value (${leaked}) reached the dry-run output"
done
# The env entries reference the Secret instead of carrying plain text.
grep -q 'name: keycloak-extra-env' "${TMP_DIR}/dryrun-env-rendered.yaml" \
  || fail "dry-run-env-redaction: the extra-env Secret is missing"
index=0
for entry in KC_SPI_DEMO_URL KC_SPI_DEMO_SESSION KC_SPI_DEMO_CLIENT \
  KC_SPI_DEMO_SIGNING_KEY KC_SPI_DEMO_DATABASE_DSN; do
  grep -A2 "name: \"${entry}\"" "${TMP_DIR}/dryrun-env-rendered.yaml" \
    | grep -q 'secretKeyRef' \
    || fail "dry-run-env-redaction: ${entry} does not reference the extra-env Secret"
  grep -Fq "extra-env-${index}: <redacted>" "${TMP_DIR}/dryrun-env-rendered.yaml" \
    || fail "dry-run-env-redaction: the ${entry} payload was not masked"
  index=$((index + 1))
done
# The Secret keys are index-based, never the env name: a boolean-like
# name such as `on` would not round-trip as an unquoted YAML key, and
# relaxed container env names (Kubernetes 1.33+) can contain characters
# a Secret key must not.
printf 'keycloak:\n  extraEnv:\n    - name: "example/name"\n      value: slash-name-check\n    - name: "on"\n      value: bool-name-check\n' \
  >"${TMP_DIR}/dryrun-env-on.yaml"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-env-on.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-env-on-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-env-redaction: the oddly named extra-env render failed"
fi
grep -Fq 'name: "example/name"' "${TMP_DIR}/dryrun-env-on-rendered.yaml" \
  || fail "dry-run-env-redaction: the slash-named env entry is missing"
grep -Fq 'key: "extra-env-0"' "${TMP_DIR}/dryrun-env-on-rendered.yaml" \
  || fail "dry-run-env-redaction: the slash-named entry does not use an index key"
grep -Fq 'name: "on"' "${TMP_DIR}/dryrun-env-on-rendered.yaml" \
  || fail "dry-run-env-redaction: the boolean-named env entry is missing"
grep -Fq 'extra-env-0: <redacted>' "${TMP_DIR}/dryrun-env-on-rendered.yaml" \
  || fail "dry-run-env-redaction: the slash-named entry payload was not masked"
grep -Fq 'extra-env-1: <redacted>' "${TMP_DIR}/dryrun-env-on-rendered.yaml" \
  || fail "dry-run-env-redaction: the boolean-named entry payload was not masked"
# extraEnv also accepts a mapping of entry objects keyed by name: both
# shapes have always rendered. The Secret keys and their secretKeyRefs
# must stay positional and matching for either shape -- a map range's
# index is the map key, which is neither Secret-key-safe nor what the
# Deployment's positional key expects.
printf 'keycloak:\n  extraEnv:\n    alpha:\n      name: KC_SPI_DEMO_URL\n      value: map-url-check\n    beta:\n      name: KC_SPI_DEMO_SESSION\n      value: map-session-check\n' \
  >"${TMP_DIR}/dryrun-env-map.yaml"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-env-map.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-env-map-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-env-redaction: the mapping-shaped extra-env render failed"
fi
grep -Fq 'name: "KC_SPI_DEMO_URL"' "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
  || fail "dry-run-env-redaction: a mapping-shaped env entry is missing"
grep -Fq 'key: "extra-env-0"' "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
  || fail "dry-run-env-redaction: the mapping-shaped entries do not use index keys"
grep -Fq 'key: "extra-env-1"' "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
  || fail "dry-run-env-redaction: the second mapping-shaped entry lost its index key"
grep -Fq 'extra-env-0: <redacted>' "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
  || fail "dry-run-env-redaction: a mapping-shaped entry payload was not masked"
grep -Fq 'extra-env-1: <redacted>' "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
  || fail "dry-run-env-redaction: the second mapping entry payload was not masked"
for map_key in extra-env-alpha extra-env-beta; do
  grep -Fq "${map_key}" "${TMP_DIR}/dryrun-env-map-rendered.yaml" \
    && fail "dry-run-env-redaction: an extra-env key was derived from the map key (${map_key})"
done
grep -A1 'name: KC_SPI_IMPORT_REALM_FILE_STRATEGY' \
  "${TMP_DIR}/dryrun-env-rendered.yaml" \
  | grep -q 'value: OVERWRITE' \
  || fail "dry-run-env-redaction: a benign env value was masked"
# Direct redactor check for the env rule, independent of the chart: a
# credential-named entry is masked and a benignly named one is kept, in
# the indentation Helm uses for container env lists. Covers well-known
# credential names (access key IDs, registry auth config) beyond the
# PASSWORD/SECRET/TOKEN family.
printf '%s\n' 'kind: Deployment' 'spec:' '  template:' \
  '    - name: APP_PASSWORD' "      value: ${env_password}-direct" \
  '    - name: AWS_ACCESS_KEY_ID' "      value: ${env_apikey}-aws" \
  '    - name: DOCKER_AUTH_CONFIG' "      value: ${env_password}-docker" \
  '    - name: "KAFKA_BROKERS"' "      value: ${env_password}-kafka" \
  '    - name: APP_MODE' '      value: foreground' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-env-direct.yaml"
for leaked in "${env_password}-direct" "${env_apikey}-aws" \
  "${env_password}-docker" "${env_password}-kafka"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-env-direct.yaml" \
    && fail "dry-run-env-redaction: the redactor kept a credential env value (${leaked})"
done
grep -q 'value: foreground' "${TMP_DIR}/dryrun-env-direct.yaml" \
  || fail "dry-run-env-redaction: the redactor masked a benign env value"

# A sensitive env value rendered as a block scalar keeps its payload on the
# indented lines after `value: |-` (a PEM in PRIVATE_KEY, a kubeconfig in
# DOCKER_AUTH_CONFIG): the value line is masked and every body line is
# dropped, with output resuming at the next env entry.
echo "checking dry-run-env-block-redaction (block-scalar env bodies stay out)"
printf '%s\n' 'kind: Deployment' 'spec:' '  template:' \
  '    - name: APP_PASSWORD' '      value: |-' \
  "        ${env_password}-block-one" "        ${env_password}-block-two" \
  '    - name: APP_MODE' '      value: foreground' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-env-block.yaml"
for leaked in "${env_password}-block-one" "${env_password}-block-two"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-env-block.yaml" \
    && fail "dry-run-env-block-redaction: a block-scalar body line was kept (${leaked})"
done
grep -Fq 'value: <redacted>' "${TMP_DIR}/dryrun-env-block.yaml" \
  || fail "dry-run-env-block-redaction: the block-scalar value line was not masked"
grep -q 'value: foreground' "${TMP_DIR}/dryrun-env-block.yaml" \
  || fail "dry-run-env-block-redaction: output did not resume after the block"

# Helm renders template comments inside env lists, so a comment line can
# sit between an env entry's name and value lines; the one-line lookahead
# for the value must skip it instead of ending the check.
echo "checking dry-run-env-comment-redaction (values after env-list comments stay out)"
printf '%s\n' 'kind: Deployment' 'spec:' '  template:' \
  '    - name: APP_PASSWORD' '      # helm renders comments in env lists' \
  "      value: ${env_password}-commented" \
  '    - name: APP_MODE' '      value: foreground' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-env-comment.yaml"
grep -Fq "${env_password}-commented" "${TMP_DIR}/dryrun-env-comment.yaml" \
  && fail "dry-run-env-comment-redaction: a value after a comment was kept"
grep -Fq '# helm renders comments in env lists' \
  "${TMP_DIR}/dryrun-env-comment.yaml" \
  || fail "dry-run-env-comment-redaction: the comment was dropped"
grep -q 'value: foreground' "${TMP_DIR}/dryrun-env-comment.yaml" \
  || fail "dry-run-env-comment-redaction: output did not resume after the comment"

# Credential-shaped names beyond the keyword list: any *_KEY-suffixed
# name and DSN/connection-string names often carry raw key material or
# an embedded password, so they are masked like the keyword names.
echo "checking dry-run-env-keyname-redaction (key and DSN env values stay out)"
signing_key=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
dsn_password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
dsn_username=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
database_dsn="postgres://${dsn_username}:${dsn_password}@db.invalid/db"
connection_string=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' 'kind: Deployment' 'spec:' '  template:' \
  '    - name: KC_SIGNING_KEY' "      value: ${signing_key}" \
  '    - name: DATABASE_DSN' \
  "      value: ${database_dsn}" \
  '    - name: DATA_CONNECTION_STRING' "      value: ${connection_string}" \
  '    - name: APP_MODE' '      value: foreground' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-env-keynames.yaml"
for leaked in "${signing_key}" "${database_dsn}" "${connection_string}"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-env-keynames.yaml" \
    && fail "dry-run-env-keyname-redaction: a key/DSN value was kept"
done
grep -q 'value: foreground' "${TMP_DIR}/dryrun-env-keynames.yaml" \
  || fail "dry-run-env-keyname-redaction: a benign value was masked"

# RBAC rules that target Secrets name the Secret in resourceNames, and the
# name is customer-supplied (netbox.apiTokenSecret carries internal
# hostnames): Secret-scoped resourceNames are masked in both list forms,
# while resourceNames of other kinds stay readable for RBAC review. A rule
# supplied through netbox.extraDeploy can order its keys freely, so the
# Secret scope must not depend on resources appearing first, and each
# resourceNames list is paired within its own rule: a five-entry list in
# the rule after a configmaps rule must not borrow its neighbour scope.
echo "checking dry-run-role-redaction (Secret resourceNames stay out)"
printf '%s\n' 'kind: Role' 'rules:' '- apiGroups: [""]' \
  '  resources: ["secrets"]' \
  '  resourceNames: ["netbox.internal.example.com"]' \
  '  verbs: ["get"]' '- apiGroups:' '  - ""' '  resources:' '  - secrets' \
  '  resourceNames:' '  - token.netbox.internal.example.com' \
  '  verbs:' '  - get' '- apiGroups:' '  - ""' '  resources:' '  - configmaps' \
  '  resourceNames:' '  - hub-access' '  verbs:' '  - get' \
  '- resourceNames: ["ordered-flow.internal.example.com"]' \
  '  resources: ["secrets"]' '  verbs: ["get"]' \
  '- resourceNames:' '  - ordered-block.internal.example.com' \
  '  resources:' '  - secrets' '  verbs:' '  - get' \
  '- resourceNames: ["ordered-visible"]' '  resources: ["configmaps"]' \
  '  verbs: ["get"]' \
  '- apiGroups: [""]' '  resources: ["configmaps"]' '  verbs: ["get"]' \
  '- apiGroups: [""]' '  resourceNames:' '  - adjacent-one' '  - adjacent-two' \
  '  - adjacent-three' '  - adjacent-four' '  - adjacent-five' \
  '  verbs: ["get"]' '  resources: ["secrets"]' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-role-direct.yaml"
for leaked in 'netbox.internal.example.com' 'token.netbox.internal.example.com' \
  'ordered-flow.internal.example.com' 'ordered-block.internal.example.com' \
  'adjacent-one' 'adjacent-two' 'adjacent-three' 'adjacent-four' \
  'adjacent-five'; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-role-direct.yaml" \
    && fail "dry-run-role-redaction: a Secret resourceName was kept (${leaked})"
done
grep -Fq 'resourceNames: [<redacted>]' "${TMP_DIR}/dryrun-role-direct.yaml" \
  || fail "dry-run-role-redaction: a flow-list Secret resourceName was not masked"
grep -Fq '  - <redacted>' "${TMP_DIR}/dryrun-role-direct.yaml" \
  || fail "dry-run-role-redaction: a block-list Secret resourceName was not masked"
grep -Fq '  - hub-access' "${TMP_DIR}/dryrun-role-direct.yaml" \
  || fail "dry-run-role-redaction: a non-Secret resourceName was masked"
grep -Fq 'resourceNames: ["ordered-visible"]' "${TMP_DIR}/dryrun-role-direct.yaml" \
  || fail "dry-run-role-redaction: an ordered non-Secret resourceName was masked"

# The same rule through the chart path: the netbox-token-seed hook Role is
# the one dry-run document that names a caller-set Secret, so an internal
# hostname set through netbox.apiTokenSecret must not survive the render.
echo "checking dry-run-role-render-redaction (seed Role Secret name stays out)"
helm template osac-infra "${INFRA_CHART_DIR}" \
  --namespace osac-infra \
  --values "${INSTALLER_DIR}/values/bmaas-ci/infra.yaml" \
  --values "${INSTALLER_DIR}/values/bmaas-netbox-ci/infra.yaml" \
  --set osacNamespace=osac \
  --set netbox.apiTokenSecret=netbox.internal.example.com 2>/dev/null \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-role-render.yaml" \
  || fail "dry-run-role-render-redaction: the infra render failed"
grep -Fq 'netbox.internal.example.com' "${TMP_DIR}/dryrun-role-render.yaml" \
  && fail "dry-run-role-render-redaction: the seed Role Secret name reached the dry run"

# Certificate dnsNames and commonName, Route hosts, the hostname lists of
# Gateway API routes, and each Gateway listener's singular hostname carry
# the caller-supplied keycloak route hostname and cluster domain, and
# caller-supplied internal hostnames cannot be told apart from
# chart-internal ones by shape, so every entry is masked -- including
# two-label service.namespace names and .svc/.cluster.local names. Helm
# renders template comments inside these lists, so the list reader must
# skip them without ending the list.
echo "checking dry-run-hostname-redaction (certificate and route hostnames stay out)"
printf '%s\n' 'kind: Certificate' 'spec:' \
  '  commonName: keycloak-keycloak.apps.internal.example.com' \
  '  dnsNames:' '  - keycloak' '  - openbao.c3i' \
  '  - keycloak.keycloak.svc.cluster.local' \
  '  - keycloak-keycloak.apps.internal.example.com' \
  'kind: Certificate' 'spec:' \
  '  dnsNames: [osac-kafka.osac-kafka.svc, mgt.hub.internal.example.com]' \
  'kind: Route' 'spec:' \
  '  host: keycloak-keycloak.apps.internal.example.com' \
  'kind: TLSRoute' 'spec:' '  hostnames:' \
  '    # comment inside the list' \
  '    - keycloak-keycloak.apps.internal.example.com' \
  '  rules: []' \
  'kind: Gateway' 'spec:' '  listeners:' '  - name: https' \
  '    hostname: gateway.internal.example.com' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-hostnames.yaml"
for leaked in 'keycloak-keycloak.apps.internal.example.com' \
  'mgt.hub.internal.example.com' 'openbao.c3i' \
  'keycloak.keycloak.svc.cluster.local' 'osac-kafka.osac-kafka.svc' \
  'gateway.internal.example.com'; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-hostnames.yaml" \
    && fail "dry-run-hostname-redaction: a hostname was kept (${leaked})"
done
grep -Fq 'commonName: <redacted>' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: the commonName was not masked"
grep -Fq 'host: <redacted>' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: the Route host was not masked"
grep -Fq 'hostname: <redacted>' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: the Gateway listener hostname was not masked"
grep -Fq 'dnsNames: [<redacted>, <redacted>]' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: a flow-list entry was not masked"
grep -Fq '  - <redacted>' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: a block-list entry was not masked"
grep -Fq '# comment inside the list' "${TMP_DIR}/dryrun-hostnames.yaml" \
  || fail "dry-run-hostname-redaction: a list comment was dropped"

# The same rules through the chart path: the keycloak route hostname
# reaches the keycloak-tls Certificate SANs, the TLSRoute SNI list, and
# the keycloak Route host, so an internal domain set through
# keycloak.route.hostname must not survive the dry-run render.
echo "checking dry-run-hostname-render-redaction (keycloak route hostname stays out)"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
  --namespace osac-infra \
  --values "${INSTALLER_DIR}/values/dev/kind-infra.yaml" \
  --set keycloak.enabled=true \
  --set keycloak.hostname=https://keycloak-keycloak.apps.internal.example.com \
  --set keycloak.route.hostname=keycloak-keycloak.apps.internal.example.com \
  2>/dev/null \
  | "${SCRIPT_DIR}/redact-secret-values.sh" \
  >"${TMP_DIR}/dryrun-hostnames-render.yaml"; then
  fail "dry-run-hostname-render-redaction: the infra render failed"
fi
grep -Fq 'keycloak-keycloak.apps.internal.example.com' \
  "${TMP_DIR}/dryrun-hostnames-render.yaml" \
  && fail "dry-run-hostname-render-redaction: the keycloak route hostname reached the dry run"
# The SAN entries are dash-list lines; chart-fixed service names inside
# ConfigMap data payloads (openbao api_addr, the CoreDNS rewrite rules)
# are not hostname fields and stay readable.
grep -Fq '  - keycloak.keycloak.svc.cluster.local' \
  "${TMP_DIR}/dryrun-hostnames-render.yaml" \
  && fail "dry-run-hostname-render-redaction: a .svc.cluster.local SAN entry reached the dry run"
grep -Fq '  - <redacted>' "${TMP_DIR}/dryrun-hostnames-render.yaml" \
  || fail "dry-run-hostname-render-redaction: no SAN entry was rendered masked"

# The extra-env values live in a Secret, and Kubernetes does not refresh
# Secret-backed env entries in a running container, so the pod template
# carries a rollout revision keyed to the Helm release revision while
# extraEnv is in use: every upgrade rolls Keycloak, so a changed value
# never lingers in a running pod. A checksum of the values would instead
# publish a guessable hash of possibly low-entropy values, so the
# annotation must not depend on the values at all.
echo "checking keycloak-extra-env-rollout (extraEnv upgrades roll the pod)"
extra_env_rollout() {
  helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "$1" 2>/dev/null \
    | grep 'rollout/extra-env'
}
printf 'keycloak:\n  extraEnv:\n    - name: KC_SPI_DEMO_URL\n      value: rollout-first\n' \
  >"${TMP_DIR}/rollout-a.yaml"
printf 'keycloak:\n  extraEnv:\n    - name: KC_SPI_DEMO_URL\n      value: rollout-second\n' \
  >"${TMP_DIR}/rollout-b.yaml"
rollout_a=$(extra_env_rollout "${TMP_DIR}/rollout-a.yaml") \
  || fail "keycloak-extra-env-rollout: the osac-infra chart render failed"
grep -Eq 'rollout/extra-env: "[0-9]+"$' <<<"${rollout_a}" \
  || fail "keycloak-extra-env-rollout: the rollout annotation is not release-revision keyed"
rollout_b=$(extra_env_rollout "${TMP_DIR}/rollout-b.yaml")
[ "${rollout_a}" = "${rollout_b}" ] \
  || fail "keycloak-extra-env-rollout: the rollout annotation depends on the env values"
grep -q 'sha256\|checksum' <<<"${rollout_a}" \
  && fail "keycloak-extra-env-rollout: the rollout annotation exposes a value hash"
# Plain grep (no -q) so the consumer reads the full stream and Helm is
# never cut short by an early-exiting reader: with pipefail, a SIGPIPEd
# Helm would flip the pipeline status and mask the failure.
helm template osac-infra "${INFRA_CHART_DIR}" \
  --namespace osac-infra \
  --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" 2>/dev/null \
  | grep 'rollout/extra-env' >/dev/null \
  && fail "keycloak-extra-env-rollout: the rollout annotation appears without extraEnv"

# extraEnv values are stringified before the shared entry list is encoded
# as JSON: the consumer decodes with fromJsonArray, which turns every JSON
# number into a float64, so a large integer set through --set (an int64)
# would lose precision and reach the Secret as an approximation.
echo "checking keycloak-extra-env-numeric (large integers keep their digits)"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    --set 'keycloak.extraEnv[0].name=KC_NUMERIC' \
    --set 'keycloak.extraEnv[0].value=9007199254740993' \
    2>"${netbox_gate_err}" >"${TMP_DIR}/dryrun-env-numeric.yaml"; then
  fail "keycloak-extra-env-numeric: the osac-infra chart render failed"
fi
grep -Fq 'extra-env-0: "9007199254740993"' "${TMP_DIR}/dryrun-env-numeric.yaml" \
  || fail "keycloak-extra-env-numeric: a large integer lost precision on the JSON round trip"

# Internal endpoint URLs reach the dry run as plain env values too (for
# example the dev-fixtures Job's MCP_RESOURCE_URL): endpoint-shaped env
# names are masked like credential-shaped ones.
echo "checking dry-run-endpoint-env-redaction (internal endpoint env values stay out)"
mcp_host="mcp-internal-$(date +%s)-$$.internal.example.com"
printf 'keycloak:\n  devFixtures:\n    enabled: true\n    mcpResourceURL: https://%s/\n' \
  "${mcp_host}" >"${TMP_DIR}/dryrun-mcp.yaml"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-mcp.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-mcp-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-endpoint-env-redaction: the osac-infra chart render failed"
fi
grep -Fq "${mcp_host}" "${TMP_DIR}/dryrun-mcp-rendered.yaml" \
  && fail "dry-run-endpoint-env-redaction: an internal endpoint env value reached the dry-run output"
grep -A1 'name: MCP_RESOURCE_URL' "${TMP_DIR}/dryrun-mcp-rendered.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-endpoint-env-redaction: the endpoint env value was not masked"

# Devstack hooks receive their target service name through INTERNAL_SVC,
# and catalog.internalApiService is a caller override, so the value can be
# an internal service name. Service-name-shaped env names are masked like
# endpoint-shaped ones; the env name itself stays readable.
echo "checking dry-run-internal-svc-redaction (service-name env values stay out)"
devstack_svc="devstack-internal-$(date +%s)-$$.internal.example.com"
printf 'catalog:\n  internalApiService: %s\n' "${devstack_svc}" \
  >"${TMP_DIR}/dryrun-devstack-svc.yaml"
if ! helm template osac-devstack "${DEVSTACK_CHART_DIR}" \
    --namespace osac \
    --set osacNamespace=osac \
    --set ui.enabled=false \
    --set awx.enabled=false \
    -f "${TMP_DIR}/dryrun-devstack-svc.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-devstack-svc-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-internal-svc-redaction: the osac-devstack chart render failed"
fi
grep -Fq "${devstack_svc}" "${TMP_DIR}/dryrun-devstack-svc-rendered.yaml" \
  && fail "dry-run-internal-svc-redaction: an internal service name reached the dry-run output"
grep -A1 'name: INTERNAL_SVC' "${TMP_DIR}/dryrun-devstack-svc-rendered.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-internal-svc-redaction: the service-name env value was not masked"
grep -A1 'name: INTERNAL_PORT' "${TMP_DIR}/dryrun-devstack-svc-rendered.yaml" \
  | grep -q 'value: "8001"' \
  || fail "dry-run-internal-svc-redaction: the service port entry was masked or lost"

# The devstack UI ConfigMap carries the fulfillment API and OIDC issuer
# endpoints as plain data entries, and the provision-tenant hook carries
# the caller-set tenant user list as TENANT_USERS. Overlays can point the
# endpoints at an internal host and put email addresses in the user list,
# so both classes must not survive the redactor.
echo "checking dry-run-devstack-ui-redaction (UI endpoints and tenant users stay out)"
devstack_ui_host="devstack-ui-$(date +%s)-$$.internal.example.com"
devstack_email="tenant-admin-$(date +%s)-$$@internal.example.com"
cat >"${TMP_DIR}/dryrun-devstack-ui.yaml" <<DEVSTACK_UI_EOF
ui:
  api:
    fulfillment:
      url: https://${devstack_ui_host}:8000
  auth:
    oidcIssuerURL: https://${devstack_ui_host}:8443/realms/osac
tenant:
  users: "tenant1_user,${devstack_email}"
DEVSTACK_UI_EOF
if ! helm template osac-devstack "${DEVSTACK_CHART_DIR}" \
    --namespace osac \
    --set osacNamespace=osac \
    --set awx.enabled=false \
    -f "${TMP_DIR}/dryrun-devstack-ui.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-devstack-ui-redaction: the osac-devstack chart render failed"
fi
for leaked in "${devstack_ui_host}" "${devstack_email}"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" \
    && fail "dry-run-devstack-ui-redaction: caller data reached the dry-run output (${leaked})"
done
grep -Fq 'FULFILLMENT_API_URL: <redacted>' "${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" \
  || fail "dry-run-devstack-ui-redaction: the fulfillment API URL was not masked"
grep -Fq 'OIDC_ISSUER_URL: <redacted>' "${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" \
  || fail "dry-run-devstack-ui-redaction: the OIDC issuer URL was not masked"
grep -Fq 'LOG_LEVEL: "info"' "${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" \
  || fail "dry-run-devstack-ui-redaction: a non-endpoint ConfigMap entry was masked"
grep -A1 'name: TENANT_USERS' "${TMP_DIR}/dryrun-devstack-ui-rendered.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-devstack-ui-redaction: the tenant user list was not masked"

# The configure-awx and provision-tenant hooks carry the caller-overridden
# execution environment image (OSAC_EE_IMAGE, which can point at an
# internal registry) and the caller-supplied tenant name (TENANT) as plain
# env values, so neither may survive the redactor.
echo "checking dry-run-devstack-awx-redaction (execution image and tenant name stay out)"
devstack_ee_registry="registry-$(date +%s)-$$.internal.example.com"
devstack_tenant="tenant-$(date +%s)-$$-customer"
cat >"${TMP_DIR}/dryrun-devstack-awx.yaml" <<DEVSTACK_AWX_EOF
awx:
  executionEnvironment:
    image: ${devstack_ee_registry}/osac/osac-aap:ci
tenant:
  name: "${devstack_tenant}"
DEVSTACK_AWX_EOF
if ! helm template osac-devstack "${DEVSTACK_CHART_DIR}" \
    --namespace osac \
    --set osacNamespace=osac \
    --set awx.enabled=true \
    -f "${TMP_DIR}/dryrun-devstack-awx.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-devstack-awx-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-devstack-awx-redaction: the osac-devstack chart render failed"
fi
for leaked in "${devstack_ee_registry}" "${devstack_tenant}"; do
  grep -Fq "${leaked}" "${TMP_DIR}/dryrun-devstack-awx-rendered.yaml" \
    && fail "dry-run-devstack-awx-redaction: caller data reached the dry-run output (${leaked})"
done
grep -A1 'name: OSAC_EE_IMAGE' "${TMP_DIR}/dryrun-devstack-awx-rendered.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-devstack-awx-redaction: the execution environment image was not masked"
grep -A1 'name: TENANT$' "${TMP_DIR}/dryrun-devstack-awx-rendered.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-devstack-awx-redaction: the tenant name was not masked"
grep -A1 'name: OSAC_EE_PULL' "${TMP_DIR}/dryrun-devstack-awx-rendered.yaml" \
  | grep -q 'value: "missing"' \
  || fail "dry-run-devstack-awx-redaction: a benign env value was masked"

# Kafka broker lists are endpoint data too: an overlay setting
# metering.kafka.brokers reaches the metering Deployment and its adapters
# as the KAFKA_BROKERS env value, whose name matches neither the
# credential-shaped nor the endpoint-shaped patterns, so it is matched
# explicitly. The render carries a runtime-generated NetBox token (masked
# as a Secret payload) because the profile enables NetBox.
echo "checking dry-run-kafka-brokers-redaction (internal broker hosts stay out)"
kafka_host="kafka-bootstrap-internal-$(date +%s)-$$.internal.example.com"
kafka_token="kafka-render-token-$(date +%s)-$$"
printf 'bmf:\n  netbox:\n    tokenValue: %s\n' "${kafka_token}" \
  >"${TMP_DIR}/dryrun-kafka-token.yaml"
if ! helm template dryrun-osac "${OSAC_CHART_DIR}" \
    --values "${OSAC_CHART_DIR}/ci/default-values.yaml" \
    --namespace osac \
    "${NETBOX_PROFILE_ARGS[@]}" \
    -f "${TMP_DIR}/dryrun-kafka-token.yaml" \
    --set "metering.kafka.brokers=${kafka_host}:9093" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-kafka-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-kafka-brokers-redaction: the osac chart render failed"
fi
grep -Fq "${kafka_host}" "${TMP_DIR}/dryrun-kafka-rendered.yaml" \
  && fail "dry-run-kafka-brokers-redaction: an internal broker host reached the dry-run output"
kafka_masked=$(grep -A1 'name: KAFKA_BROKERS' "${TMP_DIR}/dryrun-kafka-rendered.yaml" \
  | grep -c 'value: <redacted>')
[ "${kafka_masked}" -ge 2 ] \
  || fail "dry-run-kafka-brokers-redaction: a KAFKA_BROKERS value was not masked (${kafka_masked}/2)"

# Helm leaves a simple env name unquoted, but the redactor also runs over
# caller-supplied manifests (netbox.extraDeploy), where either quote style
# can appear; the exact KAFKA_BROKERS compare must survive the quotes.
echo "checking dry-run-quoted-env-name-redaction (quoted env names stay masked)"
printf '%s\n' 'kind: Deployment' 'spec:' '  template:' '    spec:' \
  '      containers:' '      - env:' \
  "        - name: 'KAFKA_BROKERS'" \
  '          value: quoted-broker.internal.example.com:9093' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-quoted-env.yaml"
grep -Fq 'quoted-broker.internal.example.com' "${TMP_DIR}/dryrun-quoted-env.yaml" \
  && fail "dry-run-quoted-env-name-redaction: a single-quoted env value was kept"
grep -A1 "name: 'KAFKA_BROKERS'" "${TMP_DIR}/dryrun-quoted-env.yaml" \
  | grep -q 'value: <redacted>' \
  || fail "dry-run-quoted-env-name-redaction: the quoted env value was not masked"

# Image overrides carry the internal registry hostname into every image
# reference the dry run prints. The registry host is masked unless it is
# a well-known public registry, so the repository and tag stay readable
# for review.
echo "checking dry-run-image-registry-redaction (internal registry hosts stay out)"
reg_host="registry-internal-$(date +%s)-$$.internal.example.com"
printf 'cliImage: %s/openshift/origin-cli:4.22\nkeycloak:\n  images:\n    keycloak: %s/keycloak/keycloak:26.6.4\n' \
  "${reg_host}" "${reg_host}" >"${TMP_DIR}/dryrun-registry.yaml"
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-registry.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-registry-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-image-registry-redaction: the osac-infra chart render failed"
fi
grep -Fq "${reg_host}" "${TMP_DIR}/dryrun-registry-rendered.yaml" \
  && fail "dry-run-image-registry-redaction: an internal registry hostname reached the dry-run output"
grep -q 'image: <redacted>/keycloak/keycloak:26.6.4' "${TMP_DIR}/dryrun-registry-rendered.yaml" \
  || fail "dry-run-image-registry-redaction: the overridden image repository was not kept readable"
grep -q 'image: <redacted>/openshift/origin-cli:4.22' "${TMP_DIR}/dryrun-registry-rendered.yaml" \
  || fail "dry-run-image-registry-redaction: the overridden cli image repository was not kept readable"
grep -q 'image: quay.io/sclorg' "${TMP_DIR}/dryrun-registry-rendered.yaml" \
  || fail "dry-run-image-registry-redaction: a public registry image was masked"
grep -q 'image: ghcr.io/openbao' "${TMP_DIR}/dryrun-registry-rendered.yaml" \
  || fail "dry-run-image-registry-redaction: a public registry image was masked"

# Container entries render as either `image:` keys or `- image:` list
# items, and a quoted value can use either quote style; the registry-host
# rule covers all of them and keeps the quoting in the output so the
# masked YAML stays valid.
echo "checking dry-run-image-list-redaction (list-item image registries stay out)"
list_reg="list-registry-$(date +%s)-$$.internal.example.com"
printf '%s\n' 'spec:' '  containers:' \
  "  - image: ${list_reg}/repo/one:1" \
  "  - image: '${list_reg}/repo/two:1'" \
  '  - image: quay.io/sclorg/cli:1' \
  | "${SCRIPT_DIR}/redact-secret-values.sh" >"${TMP_DIR}/dryrun-image-list.yaml"
grep -Fq "${list_reg}" "${TMP_DIR}/dryrun-image-list.yaml" \
  && fail "dry-run-image-list-redaction: a list-item registry host reached the dry-run output"
grep -q -- '- image: <redacted>/repo/one:1' "${TMP_DIR}/dryrun-image-list.yaml" \
  || fail "dry-run-image-list-redaction: the unquoted list-item image was not masked"
grep -q -- "- image: '<redacted>/repo/two:1'" "${TMP_DIR}/dryrun-image-list.yaml" \
  || fail "dry-run-image-list-redaction: the single-quoted list-item image was not masked"
grep -q 'image: quay.io/sclorg/cli:1' "${TMP_DIR}/dryrun-image-list.yaml" \
  || fail "dry-run-image-list-redaction: a public registry image was masked"

# The MCE image-overrides ConfigMap carries registry hostnames in its
# manifest data (the image-remote fields); the dry run must mask it like
# the other endpoint-config ConfigMaps, keeping the ConfigMap name and
# entry keys readable.
echo "checking dry-run-mce-registry-redaction (MCE override registries stay out)"
mce_reg="mce-registry-internal-$(date +%s)-$$.internal.example.com"
cat >"${TMP_DIR}/dryrun-mce.yaml" <<MCE_EOF
mce:
  enabled: true
  imageOverrides:
    - image-name: assisted-service
      image-remote: ${mce_reg}
      image-digest: sha256:c007ecc530f4bb0a43814f4373bdec6e27d1fa3698554b0935a07c086802e479
      image-key: assisted_service_9
MCE_EOF
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-mce.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-mce-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-mce-registry-redaction: the osac-infra chart render failed"
fi
grep -Fq "${mce_reg}" "${TMP_DIR}/dryrun-mce-rendered.yaml" \
  && fail "dry-run-mce-registry-redaction: an internal registry hostname reached the dry-run output"
grep -q 'name: osac-infra-mce-image-overrides' "${TMP_DIR}/dryrun-mce-rendered.yaml" \
  || fail "dry-run-mce-registry-redaction: the MCE overrides ConfigMap is missing"
grep -q 'manifest.json: <redacted>' "${TMP_DIR}/dryrun-mce-rendered.yaml" \
  || fail "dry-run-mce-registry-redaction: the overrides manifest was not masked"

# The MCE AgentServiceConfig map (osac-infra-mce-config) carries the
# osImages list, whose URLs point at internal OS image mirrors; the dry
# run must mask it like the other endpoint-config ConfigMaps, keeping the
# ConfigMap name readable.
echo "checking dry-run-mce-config-redaction (MCE osImages mirror URLs stay out)"
mce_mirror="mirror-internal-$(date +%s)-$$.internal.example.com"
cat >"${TMP_DIR}/dryrun-mce-config.yaml" <<MCE_EOF
mce:
  enabled: true
  osImages:
    - openshiftVersion: "4.22"
      version: "9.8.20260428-0"
      url: https://${mce_mirror}/rhcos-4.22-live.x86_64.iso
      cpuArchitecture: "x86_64"
MCE_EOF
if ! helm template osac-infra "${INFRA_CHART_DIR}" \
    --namespace osac-infra \
    --values "${INSTALLER_DIR}/values/vmaas-ci/infra.yaml" \
    -f "${TMP_DIR}/dryrun-mce-config.yaml" \
    | "${SCRIPT_DIR}/redact-secret-values.sh" \
    >"${TMP_DIR}/dryrun-mce-config-rendered.yaml" 2>>"${netbox_gate_err}"; then
  fail "dry-run-mce-config-redaction: the osac-infra chart render failed"
fi
grep -Fq "${mce_mirror}" "${TMP_DIR}/dryrun-mce-config-rendered.yaml" \
  && fail "dry-run-mce-config-redaction: an internal mirror URL reached the dry-run output"
grep -q 'name: osac-infra-mce-config' "${TMP_DIR}/dryrun-mce-config-rendered.yaml" \
  || fail "dry-run-mce-config-redaction: the MCE config ConfigMap is missing"
grep -q 'config.yaml: <redacted>' "${TMP_DIR}/dryrun-mce-config-rendered.yaml" \
  || fail "dry-run-mce-config-redaction: the osImages config was not masked"

echo "input validation passed"
