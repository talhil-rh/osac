{{- define "osac-infra.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "osac-infra.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "osac-infra.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "osac-infra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "osac-infra.hookLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "osac-infra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
keycloak.extraEnv accepts both the documented list of {name, value} entries
and a mapping of those entry objects keyed by name (either shape has always
rendered). The keycloak-extra-env Secret and the Deployment's secretKeyRefs
must iterate the same entries in the same order, so both ranges include this
helper: it normalizes either shape to one list -- map entries in key order,
which Go templates sort deterministically -- and returns it as JSON.
Numeric values are stringified first: the consumer decodes the JSON back with
fromJsonArray, which turns every JSON number into a float64, so a large
integer supplied through --set (an int64) would lose precision on the round
trip. Missing and null values are left untouched.
*/}}
{{- define "osac-infra.keycloakExtraEnvEntries" -}}
{{- $entries := .Values.keycloak.extraEnv -}}
{{- if kindIs "map" $entries -}}
{{- $list := list -}}
{{- range $entry := $entries -}}
{{- $list = append $list $entry -}}
{{- end -}}
{{- $entries = $list -}}
{{- end -}}
{{- $normalized := list -}}
{{- range $entry := $entries -}}
{{- if kindIs "map" $entry -}}
{{- if hasKey $entry "value" -}}
{{- $value := $entry.value -}}
{{- range $kind := list "int" "int8" "int16" "int32" "int64" "uint" "uint8" "uint16" "uint32" "uint64" "float32" "float64" -}}
{{- if kindIs $kind $value -}}
{{- $entry = set (deepCopy $entry) "value" (toString $value) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $normalized = append $normalized $entry -}}
{{- end -}}
{{- toJson $normalized -}}
{{- end -}}

{{/*
Pod security context shared by the credential-generation Jobs. The explicit
runAsNonRoot requirement applies to both the default OpenShift path and the
numeric security context used by Kind profiles.
*/}}
{{- define "osac-infra.cliJobPodSecurityContext" -}}
runAsNonRoot: true
{{- with .Values.cliJobPodSecurityContext }}
{{- with .runAsUser }}
runAsUser: {{ . }}
{{- end }}
{{- with .runAsGroup }}
runAsGroup: {{ . }}
{{- end }}
{{- with .fsGroup }}
fsGroup: {{ . }}
{{- end }}
{{- end }}
{{- end }}
