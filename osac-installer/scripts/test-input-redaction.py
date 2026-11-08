#!/usr/bin/env python3
"""Exercise offline validation diagnostics and order-independent redaction."""

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
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="osac-redaction-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.password = secrets.token_hex(24)
        self.hostname = f"{secrets.token_hex(12)}.internal.invalid"
        self.url = f"https://{secrets.token_hex(8)}:{self.password}@{self.hostname}"

    def assert_private(self, output):
        for value in (self.password, self.hostname):
            self.assertFalse(value in output, "sensitive canary reached output")

    def redact(self, manifest):
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("payload: <redacted>", result.stdout)
        self.assertIn("name: readable", result.stdout)
        self.assertIn("mode: foreground", result.stdout)

    def test_direct_document_orders(self):
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
                    manifest += "---\nkind: ConfigMap\nmetadata:\n  name: readable\ndata:\n  mode: foreground\n"
                    self.redact(manifest)

    def test_netbox_extra_deploy_real_render(self):
        for data_first in (False, True):
            with self.subTest(data_first=data_first):
                resources = []
                for kind, name in (("Secret", "readable"), ("ConfigMap", "network-ig")):
                    identity = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}}
                    payload = {"data": {"payload": self.password}}
                    resources.append({**payload, **identity} if data_first else {**identity, **payload})
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
                self.redact(result.stdout + "\n---\nkind: ConfigMap\nmetadata:\n  name: readable\ndata:\n  mode: foreground\n")

    def test_aap_validation_does_not_echo_url(self):
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

    def test_make_gate_initial_and_retry_errors_are_private(self):
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

    def test_make_gate_real_aap_error_is_private(self):
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
