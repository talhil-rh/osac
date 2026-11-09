#!/usr/bin/env python3
"""Exercise offline validation diagnostics and order-independent redaction."""

import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1]
HELM = shutil.which(os.environ.get("HELM_BIN", "helm"))


class InputRedactionTests(unittest.TestCase):
    """Regression tests for redaction and private validation diagnostics."""

    def setUp(self):
        """Create a temporary directory and the canary values used below."""
        self.temp = tempfile.TemporaryDirectory(prefix="osac-redaction-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.password = secrets.token_hex(24)
        self.username = secrets.token_hex(8)
        self.hostname = f"{secrets.token_hex(12)}.internal.invalid"
        self.url = f"https://{self.username}:{self.password}@{self.hostname}"
        self.token = secrets.token_hex(24)

    def assert_private(self, output):
        """Fail when any canary value appears in the given output."""
        for value in (self.username, self.password, self.hostname, self.token):
            self.assertFalse(value in output, "sensitive canary reached output")

    def redact(self, manifest):
        """Run the redactor and check canaries are gone and safe values kept."""
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("payload: <redacted>", result.stdout)
        self.assertIn("name: readable", result.stdout)
        self.assertIn("mode: foreground", result.stdout)

    def test_direct_document_orders(self):
        """Check payload masking for every kind regardless of field order."""
        for kind, name in (("Secret", "readable"), ("ConfigMap", "network-ig"),
                           ("ConfigMap", "osac-infra-evpn-config"),
                           ("ConfigMap", "osac-infra-mce-config"),
                           ("ConfigMap", "osac-infra-mce-image-overrides")):
            for order in ("identity-first", "data-first", "name-last"):
                with self.subTest(kind=kind, order=order):
                    identity = f"kind: {kind}\nmetadata:\n  name: {name}\n"
                    payload = f"data:\n  payload: {self.url}\n"
                    if order == "identity-first":
                        manifest = identity + payload
                    elif order == "data-first":
                        manifest = payload + identity
                    else:
                        manifest = f"kind: {kind}\n{payload}metadata:\n  name: {name}\n"
                    if kind == "Secret":
                        manifest += f"stringData:\n  payload: |\n    {self.password}\n"
                    manifest += "---\ndata:\n  mode: foreground\nkind: ConfigMap\nmetadata:\n  name: readable\n"
                    self.redact(manifest)

    def test_credential_configmap_values_are_masked(self):
        """Check credential-shaped ConfigMap values, including block scalars."""
        manifest = (
            "kind: ConfigMap\nmetadata:\n  name: netbox-integration\n"
            f"data:\n  apiToken: |\n    {self.token}\n"
            f"  adminPassword: {self.password}\n"
            f"  SECRET_KEY: {self.password}\n"
            "  plainValue: readable\n"
            "---\n"
            "data:\n"
            f"  apiToken: {self.token}\n"
            "  plainValue: readable\n"
            "kind: ConfigMap\nmetadata:\n  name: data-first\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("apiToken: <redacted>", result.stdout)
        self.assertIn("adminPassword: <redacted>", result.stdout)
        self.assertIn("SECRET_KEY: <redacted>", result.stdout)
        self.assertEqual(result.stdout.count("plainValue: readable"), 2)
        self.assertNotIn("apiToken: |", result.stdout)

    def test_netbox_extra_deploy_real_render(self):
        """Check a real render whose extraDeploy payload precedes its identity."""
        for data_first in (False, True):
            with self.subTest(data_first=data_first):
                resources = []
                for kind, name in (("Secret", "readable"), ("ConfigMap", "network-ig")):
                    identity = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}}
                    payload = {"data": {"payload": self.password}}
                    resources.append({**payload, **identity} if data_first else {**identity, **payload})
                resources.append({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "netbox-integration"},
                    "data": {"apiToken": f"{self.token}\n", "plainValue": "readable"},
                })
                values = self.directory / "extra.json"
                values.write_text(json.dumps({"netbox": {"extraDeploy": resources}}))
                result = subprocess.run(
                    [HELM, "template", "osac-infra", str(INSTALLER / "charts/osac-infra"),
                     "-f", str(INSTALLER / "values/bmaas-ci/infra.yaml"),
                     "-f", str(INSTALLER / "values/bmaas-netbox-ci/infra.yaml"),
                     "-f", str(values), "--set", "osacNamespace=osac"],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, "real infra render failed")
                self.assertTrue(self.password in result.stdout, "extraDeploy fixture was not rendered")
                self.assertTrue(self.token in result.stdout, "credential ConfigMap fixture was not rendered")
                self.redact(result.stdout + "\n---\nkind: ConfigMap\nmetadata:\n  name: readable\ndata:\n  mode: foreground\n")

    def test_comments_quoted_kinds_and_document_boundaries(self):
        """Check masking survives comments, quoted kinds, and separators."""
        for kind, name in (("Secret", "readable"), ("ConfigMap", "network-ig"),
                           ("ConfigMap", "osac-infra-evpn-config"),
                           ("ConfigMap", "osac-infra-mce-config"),
                           ("ConfigMap", "osac-infra-mce-image-overrides")):
            with self.subTest(kind=kind):
                manifest = (
                    f'data: # payload follows\n  payload: {self.url}\n'
                    f'  name: {self.password}\nkind: "{kind}"\nmetadata:\n'
                    f'# ordinary metadata comment\n  namespace: osac\n  name: "{name}"\n'
                    '--- # adjacent safe document\nkind: ConfigMap\nmetadata:\n'
                    '  name: readable\ndata:\n  mode: foreground\n'
                )
                self.redact(manifest)

    def test_payload_comments_do_not_end_masking(self):
        """Check a comment inside a payload does not end payload masking."""
        self.redact(
            f'kind: Secret\nmetadata:\n  name: readable\nstringData:\n'
            f'# ordinary payload comment\n  payload: |\n    {self.password}\n'
            f'data:\n  payload: {self.url}\n---\nkind: ConfigMap\nmetadata:\n'
            '  name: readable\ndata:\n  mode: foreground\n'
        )

    def test_masking_state_resets_between_documents(self):
        """Check masking state from one document does not leak into the next."""
        self.redact(
            f'kind: Secret\nmetadata:\n  name: readable\ndata:\n  payload: {self.url}\n'
            '---\nkind: Deployment\nspec:\n  - name: API_TOKEN\n'
            '---\nkind: ConfigMap\nmetadata:\n  name: readable\ndata:\n'
            '  mode: foreground\n  value: visible\n'
        )

    def test_failure_diagnostics_do_not_echo_canaries(self):
        """Check a failed assertion's diagnostic output does not echo canaries."""
        output = io.StringIO()
        case = unittest.FunctionTestCase(lambda: self.assert_private(self.url))
        result = unittest.TextTestRunner(stream=output).run(case)
        self.assertEqual(len(result.failures), 1)
        self.assert_private(output.getvalue())

    def test_aap_validation_does_not_echo_url(self):
        """Check AAP URL validation rejects a credential URL without echoing it."""
        values = self.directory / "aap.json"
        values.write_text(json.dumps({"instanceGroups": {"networkFulfillment": {
            "config": {"NETRIS_CONTROLLER_URL": self.url}}}}))
        result = subprocess.run(
            [HELM, "template", "aap", str(INSTALLER.parent / "osac-aap/charts/aap"),
             "-f", str(values)], text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("NETRIS_CONTROLLER_URL", result.stderr)
        self.assertIn("https://", result.stderr)
        self.assertNotIn("without embedded credentials", result.stderr)

    def test_aap_url_validation_policy_is_unchanged(self):
        """Check a credential-free URL still renders under the existing policy."""
        values = self.directory / "aap-valid.json"
        values.write_text(json.dumps({"instanceGroups": {"networkFulfillment": {
            "config": {"NETRIS_CONTROLLER_URL": f"https://{self.username}@{self.hostname}/api"}}}}))
        result = subprocess.run(
            [HELM, "template", "aap", str(INSTALLER.parent / "osac-aap/charts/aap"),
             "-f", str(values)], text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "the existing URL policy changed")

    def test_make_gate_initial_and_retry_errors_are_private(self):
        """Check the make gate keeps a failing render's error private, with or
        without the Secret-injection retry."""
        chart = self.directory / "chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: diagnostic\nversion: 0.1.0\n")
        values = self.directory / "values.json"
        values.write_text(json.dumps({"rejected": self.url}))
        (chart / "templates/failure.yaml").write_text('{{ fail .Values.rejected }}\n')
        calls = self.directory / "render-calls"
        for retry in (False, True):
            with self.subTest(retry=retry):
                binary = self.directory / "bin"
                binary.mkdir(exist_ok=True)
                wrapper = binary / "helm"
                wrapper.write_text(
                    '#!/usr/bin/env bash\nset -euo pipefail\n'
                    'if [[ "$1" == template && "$2" == osac ]]; then\n'
                    '  echo render >> "$RENDER_CALLS"\n'
                    + ('  if [[ "$*" != *"bmf.netbox.tokenValue="* ]]; then\n'
                       '    echo "netbox.tokenValue is required when Secret" >&2\n'
                       '    exit 1\n  fi\n' if retry else '')
                    + '  exec "$REAL_HELM" template diagnostic "$ERROR_CHART" -f "$ERROR_VALUES"\n'
                    'fi\nexec "$REAL_HELM" "$@"\n'
                )
                wrapper.chmod(0o755)
                env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
                       "REAL_HELM": HELM, "ERROR_CHART": str(chart), "ERROR_VALUES": str(values),
                       "RENDER_CALLS": str(calls)}
                calls.write_text("")
                result = subprocess.run(
                    ["make", "--no-print-directory", "-C", str(INSTALLER),
                     "-o", "helm-osac-deps", "-o", "helm-infra-deps", "validate-inputs",
                     "PLATFORM=kind", "PROFILE=dev", "NS=osac"],
                    env=env, text=True, capture_output=True, timeout=60,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assert_private(result.stdout + result.stderr)
                self.assertIn("offline OSAC chart", result.stderr)
                self.assertIn("no cluster changes", result.stderr)
                self.assertEqual(len(calls.read_text().splitlines()), 2 if retry else 1)

    def test_offline_render_error_reports_schema_path_without_values(self):
        """Check unmatched schema failures name the path and drop the value."""
        cases = (
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                f"osac:\n- aap.bootstrap.backoffLimit: {self.password}\n",
                "aap.bootstrap.backoffLimit: violates the values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                f"osac:\n- at '/global/fulfillmentTrust': {self.url}\n",
                "global/fulfillmentTrust: violates the values schema",
            ),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; offline_render_error "$2"',
                     "bash", str(INSTALLER / "scripts/lib.sh"), message],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0)
                self.assert_private(result.stdout + result.stderr)
                self.assertIn("offline OSAC chart", result.stderr)
                self.assertIn(expected, result.stderr)
        # The three specific diagnostics still win over the path fallback.
        specific = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"),
             "bmf.netbox.tokenValue: Invalid type: got number, want string"],
            text=True, capture_output=True,
        )
        self.assertIn("bmf.netbox.tokenValue: Invalid type; expected string",
                      specific.stderr)

    def test_make_gate_real_aap_error_is_private(self):
        """Check the real AAP render failure through the make gate stays private."""
        values = self.directory / "osac.json"
        values.write_text(json.dumps({"aap": {"instanceGroups": {"networkFulfillment": {
            "config": {"NETRIS_CONTROLLER_URL": self.url}}}}}))
        result = subprocess.run(
            ["make", "--no-print-directory", "-C", str(INSTALLER),
             "-o", "helm-osac-deps", "-o", "helm-infra-deps", "validate-inputs",
             "PLATFORM=kind", "PROFILE=dev", "NS=osac", f"INSTANCE_VALUES_EXTRA=-f {values}"],
            env=os.environ,
            text=True, capture_output=True, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("offline OSAC chart", result.stderr)


if __name__ == "__main__":
    unittest.main()
