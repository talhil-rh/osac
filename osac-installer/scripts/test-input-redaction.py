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
HELM4 = shutil.which(os.environ.get("HELM4_BIN", "helm4"))


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
            f"  signingKey: {self.token}\n"
            f"  key: {self.token}\n"
            f"  signing-key: {self.token}\n"
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
        self.assertIn("signingKey: <redacted>", result.stdout)
        self.assertIn("\n  key: <redacted>\n", result.stdout)
        self.assertIn("signing-key: <redacted>", result.stdout)
        self.assertEqual(result.stdout.count("plainValue: readable"), 2)
        self.assertNotIn("apiToken: |", result.stdout)

    def test_configmap_file_payload_credentials_are_masked(self):
        """Check credential lines inside ConfigMap file payloads are masked."""
        manifest = (
            "kind: ConfigMap\nmetadata:\n  name: netbox-file-config\n"
            "data:\n  netbox.conf: |\n"
            "    [database]\n"
            "    host = netbox-db\n"
            f"    password = {self.password}\n"
            f"    token = {self.token}\n"
            f"    export DB_PASSWORD={self.password}\n"
            f"    - token: {self.token}\n"
            f"    encryption_key: {self.password}\n"
            f"    export SIGNING_KEY={self.token}\n"
            f"    signingKey: {self.token}\n"
            f"    private_key: |\n"
            "      key-material-line\n"
            f"      {self.token}\n"
            "    certificate: |\n"
            "      readable-cert-line\n"
            f"    Authorization: Bearer {self.token}\n"
            f"    uri = postgres://user:{self.password}@db/app\n"
            f"    api = https://netbox.example/api/?token={self.token}"
            "&author=readable\n"
            f"    endpoint = https://netbox.example/api"
            f"?api_key={self.password}\n"
            "    paged = https://netbox.example/api?page=2&limit=10\n"
            f"    options = user=dbuser password={self.password} & tls=on\n"
            f"    connection: server={self.hostname} port=5432\n"
            f"    server = https://{self.hostname}/api\n"
            f"    peer = node1.{self.hostname}\n"
            f'    {{"password":"{self.token}"}}\n'
            "    key: readable-key\n"
            "    tls.key: /etc/tls/tls.key\n"
            "    author = readable\n"
            "    ttl = 300\n"
            "  settings.yaml: |\n"
            f'    "client_secret": "{self.token}"\n'
            "    oauth: oidc\n"
            "---\n"
            "data:\n"
            "  app.conf: |\n"
            f"    db_password={self.password}\n"
            "    log_level=debug\n"
            "kind: ConfigMap\nmetadata:\n  name: data-first\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("password = <redacted>", result.stdout)
        self.assertIn("token = <redacted>", result.stdout)
        self.assertIn('"client_secret": <redacted>', result.stdout)
        self.assertIn("db_password=<redacted>", result.stdout)
        self.assertIn("export DB_PASSWORD=<redacted>", result.stdout)
        self.assertIn("- token: <redacted>", result.stdout)
        self.assertIn("encryption_key: <redacted>", result.stdout)
        self.assertIn("export SIGNING_KEY=<redacted>", result.stdout)
        self.assertIn("signingKey: <redacted>", result.stdout)
        self.assertIn("private_key: <redacted>", result.stdout)
        self.assertNotIn("key-material-line", result.stdout)
        self.assertIn("readable-cert-line", result.stdout)
        self.assertIn("Authorization: <redacted>", result.stdout)
        self.assertIn("postgres://<redacted>@db/app", result.stdout)
        self.assertIn("?token=<redacted>&author=readable", result.stdout)
        self.assertIn("endpoint = <redacted>", result.stdout)
        self.assertIn("user=dbuser password=<redacted> & tls=on", result.stdout)
        self.assertIn("connection: server=<redacted> port=5432", result.stdout)
        self.assertIn("server = <redacted>", result.stdout)
        self.assertIn("peer = <redacted>", result.stdout)
        self.assertIn('{"password":"<redacted>"}', result.stdout)
        for readable in ("host = netbox-db", "author = readable", "ttl = 300",
                         "oauth: oidc", "log_level=debug",
                         "key: readable-key", "tls.key: /etc/tls/tls.key",
                         "paged = https://<redacted>/api"
                         "?page=2&limit=10"):
            self.assertIn(readable, result.stdout)

    def test_single_line_configmap_file_credentials_are_masked(self):
        """Check one-line file payloads are masked as a whole."""
        manifest = (
            "kind: ConfigMap\nmetadata:\n  name: single-line-file\n"
            "data:\n"
            f"  netbox.conf: host = netbox-db password = {self.password}\n"
            f"  events.json: '{{\"token\":\"{self.token}\","
            "\"author\":\"readable\"}'\n"
            f"  nested.json: '{{\"a\":{{\"password\":\"{self.token}\"}}}}'\n"
            f"  query.conf: https://netbox-db/app?token={self.token}\n"
            "  settings.conf: author = readable\n"
            "  plain.conf: hello = world\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        for masked in ("netbox.conf: <redacted>", "events.json: <redacted>",
                       "nested.json: <redacted>", "query.conf: <redacted>"):
            self.assertIn(masked, result.stdout)
        self.assertIn("settings.conf: author = readable", result.stdout)
        self.assertIn("plain.conf: hello = world", result.stdout)

    def test_flow_style_secret_payloads_are_masked(self):
        """Check flow-style data/stringData maps are masked as a whole."""
        manifest = (
            "kind: Secret\nmetadata:\n  name: flow-secret\n"
            f"stringData: {{password: {self.password}}}\n"
            "---\n"
            "kind: Secret\nmetadata:\n  name: flow-multiline\n"
            f"data: {{password: {self.password},\n"
            f"  token: {self.token}}}\n"
            "---\nkind: ConfigMap\nmetadata:\n  name: readable\n"
            "data:\n  mode: foreground\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("stringData: {<redacted>}"), 1)
        self.assertEqual(result.stdout.count("data: {<redacted>}"), 1)
        self.assertIn("name: flow-multiline", result.stdout)
        self.assertIn("name: readable", result.stdout)

    def test_nested_block_scalar_under_credential_key_is_dropped(self):
        """Check a block scalar value under a credential key loses its body."""
        manifest = (
            "kind: ConfigMap\nmetadata:\n  name: nested-scalars\n"
            "data:\n  settings.yaml: |\n"
            "    token: |-\n"
            f"      {self.token}\n"
            "    password: >\n"
            f"      {self.password}\n"
            "    author = readable\n"
            "    certificate: |\n"
            "      certificate-body\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("token: <redacted>", result.stdout)
        self.assertIn("password: <redacted>", result.stdout)
        self.assertIn("author = readable", result.stdout)
        self.assertIn("certificate-body", result.stdout)

    def test_url_userinfo_is_masked_outside_payloads(self):
        """Check userinfo is masked in ConfigMap and env values."""
        url = f"postgres://user:{self.password}@db/app"
        manifest = (
            "kind: ConfigMap\nmetadata:\n  name: netbox-integration\n"
            f"data:\n  uri: {url}\n"
            "  mode: foreground\n"
            "---\n"
            "kind: Deployment\nmetadata:\n  name: web\n"
            "spec:\n  containers:\n    - name: app\n      env:\n"
            "        - name: DATABASE_URI\n"
            f"          value: {url}\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("postgres://<redacted>@db/app"), 2)
        self.assertIn("mode: foreground", result.stdout)

    def test_env_value_masking_is_order_independent(self):
        """Check env masking covers value-before-name and flow items."""
        manifest = (
            "kind: Deployment\nmetadata:\n  name: web\n"
            "spec:\n  containers:\n    - name: app\n      env:\n"
            f"        - value: {self.token}\n          name: DB_PASSWORD\n"
            f"        - {{name: API_TOKEN, value: {self.token}}}\n"
            f"        - {{value: {self.token}, name: API_TOKEN}}\n"
            f"        - {{username: plain, name: API_TOKEN, value: {self.token}}}\n"
            f"        - {{subvalue: plain, name: API_TOKEN, value: {self.token}}}\n"
            "        - {name: PLAIN_SETTING, value: readable-flow}\n"
            f'        - {{name: DB_PASSWORD, value: "abc\\"{self.token},tail",'
            " other: x}\n"
            f"        - {{name: API_TOKEN, value: 'abc''{self.token},tail',"
            " other: y}\n"
            f"        - name: BIND_PASSWORD\n          value: {self.token}\n"
            "        - value: |\n"
            "            block-body-must-not-print\n"
            "          name: DB_PASSWORD\n"
        )
        result = subprocess.run(
            [str(INSTALLER / "scripts/redact-secret-values.sh")],
            input=manifest, text=True, capture_output=True, check=True,
        )
        self.assert_private(result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("value: <redacted>"), 9)
        self.assertIn(
            "{name: PLAIN_SETTING, value: readable-flow}", result.stdout
        )
        self.assertIn("name: DB_PASSWORD", result.stdout)
        self.assertNotIn("block-body-must-not-print", result.stdout)

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
                self.assertIn("offline chart rendering failed", result.stderr)
                self.assertIn("no cluster changes", result.stderr)
                self.assertEqual(len(calls.read_text().splitlines()), 2 if retry else 1)

    def test_offline_render_error_reports_template_location_without_message(self):
        """Check a template check failure names its location, not its value."""
        message = (
            "Error: execution error at "
            "(osac/templates/networking.yaml:42:7): invalid peer "
            f"{self.hostname}\n\nUse --debug flag to render out invalid YAML\n"
        )
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"), message],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("offline chart rendering failed", result.stderr)
        self.assertIn(
            "template check failed in osac/templates/networking.yaml:42:7"
            " (message suppressed)",
            result.stderr,
        )

    def test_offline_render_error_ignores_embedded_location(self):
        """Check a path-shaped token in the message is never printed."""
        message = (
            "Error: execution error at "
            "(osac/templates/validate-values.yaml:9:1): rejected "
            f"execution error at ({self.hostname}:3:4): {self.token}\n"
        )
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"), message],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn(
            "template check failed in "
            "osac/templates/validate-values.yaml:9:1 (message suppressed)",
            result.stderr,
        )

    def test_offline_render_error_uses_first_error_line_only(self):
        """Check only the first Helm error line can name a location."""
        location = (
            "template check failed in "
            "osac/templates/validate-values.yaml:9:1 (message suppressed)"
        )
        for prefix in ("", "WARNING: This chart is deprecated\n"):
            with self.subTest(prefix=prefix):
                message = (
                    prefix
                    + "Error: execution error at "
                    "(osac/templates/validate-values.yaml:9:1): rejected\n"
                    f"Error: execution error at ({self.hostname}:3:4): "
                    f"{self.token}\n"
                )
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; offline_render_error "$2"',
                     "bash", str(INSTALLER / "scripts/lib.sh"), message],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0)
                self.assert_private(result.stdout + result.stderr)
                self.assertIn(location, result.stderr)
                self.assertEqual(
                    result.stderr.count("template check failed in"), 1)
        message = (
            "Error: values don't meet the specifications of the schema(s)"
            " in the following chart(s):\n"
            f"osac:\n- at '/global/x': {self.hostname}\n"
            f"Error: execution error at ({self.hostname}:1:2): {self.token}\n"
        )
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"), message],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertNotIn("template check failed in", result.stderr)

    def test_offline_render_error_ignores_echoed_schema_paths(self):
        """Check path-shaped message text is never reported as a path."""
        cases = (
            (
                "Error: execution error at (osac/templates/x.yaml:1:3):"
                " rejected\n"
                f"- at '/{self.hostname}/path': value\n",
                "template check failed in osac/templates/x.yaml:1:3"
                " (message suppressed)",
                False,
            ),
            (
                "Error: values don't meet the specifications of the"
                " schema(s) in the following chart(s):\nosac:\n"
                "- at '/global/real': rejected\n"
                f"- at '/{self.hostname}/path': value\n",
                "global/real: violates the values schema",
                True,
            ),
        )
        for message, expected, schema_reported in cases:
            with self.subTest(expected=expected):
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; offline_render_error "$2"',
                     "bash", str(INSTALLER / "scripts/lib.sh"), message],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0)
                self.assert_private(result.stdout + result.stderr)
                self.assertIn(expected, result.stderr)
                if not schema_reported:
                    self.assertNotIn(
                        "violates the values schema", result.stderr)

    def test_offline_render_error_stops_after_unmatched_schema_item(self):
        """Check an unrecognized first schema item ends the scan."""
        message = (
            "Error: values don't meet the specifications of the schema(s)"
            " in the following chart(s):\n"
            "osac:\n"
            "- password field: Invalid type. Expected: integer,"
            " given: string\n"
            f"- at '/{self.hostname}/echoed': got string, want integer\n"
        )
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"), message],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertNotIn("violates the values schema", result.stderr)

    def test_make_gate_infra_error_is_private(self):
        """Check a failing infra render stays private through the make gate."""
        binary = self.directory / "bin"
        binary.mkdir(exist_ok=True)
        wrapper = binary / "helm"
        wrapper.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\n'
            'if [[ "$1" == template && "$2" == osac-infra ]]; then\n'
            '  echo "Error: execution error at '
            '(osac-infra/templates/networking.yaml:7:3): $REJECTED" >&2\n'
            '  echo "Use --debug flag to render out invalid YAML" >&2\n'
            '  exit 1\n'
            'fi\nexec "$REAL_HELM" "$@"\n'
        )
        wrapper.chmod(0o755)
        env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
               "REAL_HELM": HELM, "REJECTED": self.hostname}
        result = subprocess.run(
            ["make", "--no-print-directory", "-C", str(INSTALLER),
             "-o", "helm-osac-deps", "-o", "helm-infra-deps", "validate-inputs",
             "PLATFORM=kind", "PROFILE=dev", "NS=osac"],
            env=env, text=True, capture_output=True, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn(
            "template check failed in osac-infra/templates/networking.yaml:7:3",
            result.stderr,
        )
        self.assertIn("no cluster changes", result.stderr)

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
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                f"osac:\n- at '/operator/fabricDomainInventory/{self.hostname}':"
                " must be non-empty\n",
                "operator.fabricDomainInventory: violates the values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                f"osac:\n- operator.fabricDomainInventory.{self.hostname}:"
                " must be non-empty\n",
                "operator.fabricDomainInventory: violates the values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                f"osac:\n- operator.vendorControllers.{self.hostname}:"
                " must be non-empty\n",
                "operator.vendorControllers: violates the values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                "osac:\n- at '/operator/vendorControllers/"
                f"{self.hostname}/endpoint': got string, want integer\n",
                "operator.vendorControllers: violates the values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                "osac:\n- at '/operator/networkManagers/k8sManagers/"
                f"{self.hostname}/endpoint': got string, want integer\n",
                "operator.networkManagers.k8sManagers: violates the"
                " values schema",
            ),
            (
                "Error: values don't meet the specifications of the schema(s)"
                " in the following chart(s):\n"
                "osac:\n- operator.stall.workersJoiningByInstanceType."
                f"{self.hostname}: Invalid type\n",
                "operator.stall.workersJoiningByInstanceType: violates the"
                " values schema",
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
                self.assertIn("offline chart rendering failed", result.stderr)
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

    def assert_real_schema_error_is_private(self, helm):
        """Feed a real Helm schema failure through the private gate."""
        chart = self.directory / "schema-chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text(
            "apiVersion: v2\nname: schema-chart\nversion: 0.1.0\n")
        (chart / "values.yaml").write_text("password: 1\n")
        (chart / "values.schema.json").write_text(json.dumps({
            "type": "object",
            "properties": {"password": {"type": "integer"}},
            "required": ["password"],
        }))
        (chart / "templates" / "probe.yaml").write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\n")
        render = subprocess.run(
            [helm, "template", "release", str(chart),
             "--set", f"password={self.password}"],
            text=True, capture_output=True,
        )
        self.assertNotEqual(render.returncode, 0)
        self.assertIn("values don", render.stderr)
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; offline_render_error "$2"',
             "bash", str(INSTALLER / "scripts/lib.sh"), render.stderr],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assert_private(result.stdout + result.stderr)
        self.assertIn("offline chart rendering failed", result.stderr)
        self.assertIn("password: violates the values schema", result.stderr)

    @unittest.skipUnless(HELM, "helm 3 is not installed")
    def test_offline_render_error_real_helm3_schema_error_is_private(self):
        """Check a real Helm 3 schema failure names the path, not the value."""
        self.assert_real_schema_error_is_private(HELM)

    @unittest.skipUnless(HELM4, "helm 4 is not installed")
    def test_offline_render_error_real_helm4_schema_error_is_private(self):
        """Check a real Helm 4 schema failure names the path, not the value."""
        self.assert_real_schema_error_is_private(HELM4)

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
        self.assertIn("offline chart rendering failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
