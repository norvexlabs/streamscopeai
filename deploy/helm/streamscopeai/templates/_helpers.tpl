{{/* Chart name / fullname conventions. */}}
{{- define "streamscope.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "streamscope.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "streamscope.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "streamscope.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "streamscope.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: streamscopeai
{{- end -}}

{{/* Per-component selector labels. */}}
{{- define "streamscope.selectorLabels" -}}
app.kubernetes.io/name: {{ include "streamscope.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
  A release image by its key in stowage.yaml, pinned by digest. `stowage ship`
  appends the `stowage:` block (registry + every image's repository and digest)
  to values.yaml, and `ssai-stow k8s` sets `stowage.registry` to the prefix
  the release is pulled from, so the chart never names a tag.
  Caller passes a dict with "root" + "key".
*/}}
{{- define "streamscope.image" -}}
{{- include "streamscope.requireStowage" .root -}}
{{- $img := required (printf "stowage.images.%s is not set" .key) (index (required "stowage.images is not set" .root.Values.stowage.images) .key) -}}
{{- printf "%s/%s@%s" (required "stowage.registry is not set" .root.Values.stowage.registry) $img.repository $img.digest -}}
{{- end -}}

{{/* Refuses to render without the `stowage:` block: a chart not installed by ssai-stow. */}}
{{- define "streamscope.requireStowage" -}}
{{- if not .Values.stowage -}}
{{- fail "stowage values are not set: install a release shipped by stowage, with ssai-stow k8s install" -}}
{{- end -}}
{{- end -}}

{{/*
  The pull Secrets: the installer's pull account (`stowage.pullSecret`, absent
  when the registry needs none), then any the operator adds for a mirror.
*/}}
{{- define "streamscope.imagePullSecrets" -}}
{{- $names := list -}}
{{- include "streamscope.requireStowage" . -}}
{{- with .Values.stowage.pullSecret -}}{{- $names = append $names . -}}{{- end -}}
{{- range .Values.imagePullSecrets -}}{{- $names = append $names .name -}}{{- end -}}
{{- if $names }}
imagePullSecrets:
{{- range $names }}
  - name: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
  Per-host TLS secret name. Truncated to the 63-char object-name limit so a long
  release name + long FQDN can't produce a name cert-manager would reject.
  Caller passes a dict with "root" + "host".
*/}}
{{- define "streamscope.tlsSecretName" -}}
{{- printf "%s-%s-tls" (include "streamscope.fullname" .root) (regexReplaceAll "[^a-zA-Z0-9]+" .host "-") | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
  The Secret the installer writes for this release (`<release>-stowage`): the
  generated secrets and every Kubernetes input, as KEY: value. Each container is
  given only the keys it reads, one secretKeyRef at a time — never envFrom.
*/}}
{{- define "streamscope.secretName" -}}
{{- include "streamscope.requireStowage" . -}}
{{- required "stowage.secret is not set: install with ssai-stow k8s install" .Values.stowage.secret -}}
{{- end -}}

{{/*
  DB_MANAGE_APP_ROLE: explicit value wins; else true ONLY for embedded (mirrors
  the appliance — migration 001 creates streamscope_app with a placeholder for
  admin-api to sync). external + cnpg own the runtime role out-of-band, so
  admin-api must never ALTER it → false.
*/}}
{{- define "streamscope.manageAppRole" -}}
{{- if not (kindIs "invalid" .Values.postgres.manageAppRole) -}}
{{- .Values.postgres.manageAppRole -}}
{{- else if eq .Values.postgres.mode "embedded" -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/* In-cluster Postgres service name (embedded mode) / CloudNativePG cluster name (cnpg mode). */}}
{{- define "streamscope.pgServiceName" -}}
{{- printf "%s-postgres" (include "streamscope.fullname" .) -}}
{{- end -}}

{{/* The runtime role's credentials for cnpg (basic-auth: streamscope_app + the release's POSTGRES_APP_PASSWORD). */}}
{{- define "streamscope.cnpgRuntimeSecretName" -}}
{{- printf "%s-runtime" (include "streamscope.pgServiceName" .) -}}
{{- end -}}

{{/* The migration role's credentials for cnpg (basic-auth: streamscope + the release's POSTGRES_PASSWORD). */}}
{{- define "streamscope.cnpgOwnerSecretName" -}}
{{- printf "%s-owner" (include "streamscope.pgServiceName" .) -}}
{{- end -}}

{{/*
  The two DB-URL env entries for admin-api. external: the two URLs are secret
  inputs of the release. embedded and cnpg: built from the release's two
  generated passwords (alphanumeric, so they need no URL escaping), through
  Kubernetes' $(VAR) expansion of the entries defined just before them —
  against the in-cluster service (embedded) or the cluster's read-write service
  (cnpg, whose managed roles `streamscope` and `streamscope_app` take the same
  two passwords, so a cluster created again from a backup is reached with the
  credentials admin-api already holds).
*/}}
{{- define "streamscope.dbUrlEnv" -}}
{{- if has .Values.postgres.mode (list "cnpg" "embedded") -}}
{{- $cnpg := eq .Values.postgres.mode "cnpg" -}}
{{- $host := ternary (printf "%s-rw" (include "streamscope.pgServiceName" .)) (include "streamscope.pgServiceName" .) $cnpg -}}
{{- $db := ternary .Values.postgres.cnpg.database .Values.postgres.embedded.database $cnpg -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "streamscope.secretName" . }}
      key: POSTGRES_PASSWORD
- name: POSTGRES_APP_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "streamscope.secretName" . }}
      key: POSTGRES_APP_PASSWORD
- name: MIGRATION_DATABASE_URL
  value: {{ printf "postgres://streamscope:$(POSTGRES_PASSWORD)@%s:5432/%s" $host $db | quote }}
- name: DATABASE_URL
  value: {{ printf "postgres://streamscope_app:$(POSTGRES_APP_PASSWORD)@%s:5432/%s" $host $db | quote }}
{{- else -}}
{{- /* The two URLs are optional inputs (the other modes need neither), so an
  external install given none is refused here, naming them, rather than by a
  readiness wait that times out. `lookup` is empty without a cluster (helm
  template), where nothing can be checked. */ -}}
{{- $s := lookup "v1" "Secret" .Release.Namespace (include "streamscope.secretName" .) -}}
{{- if $s -}}
{{- range $k := list "MIGRATION_DATABASE_URL" "DATABASE_URL" -}}
{{- if not (index ($s.data | default dict) $k) -}}
{{- fail (printf "postgres.mode=external needs the %s input: give it to the installer (--set %s=…, or --answers), or choose another postgres.mode" $k $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
- name: MIGRATION_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "streamscope.secretName" . }}
      key: MIGRATION_DATABASE_URL
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "streamscope.secretName" . }}
      key: DATABASE_URL
{{- end -}}
{{- end -}}

{{/* Internal admin-api base URL (ClusterIP). */}}
{{- define "streamscope.adminApiUrl" -}}
{{- printf "http://%s-admin-api:%d" (include "streamscope.fullname" .) (int .Values.adminApi.port) -}}
{{- end -}}

{{/* admin-ui public origin (the console hostname over https). */}}
{{- define "streamscope.adminUiOrigin" -}}
{{- printf "https://%s" .Values.hostnames.adminUi -}}
{{- end -}}

{{/* Proxy public URL bootstrap seed (gateway hostname over https). */}}
{{- define "streamscope.proxyPublicUrl" -}}
{{- printf "https://%s" .Values.hostnames.proxy -}}
{{- end -}}

{{/*
  RATE_LIMIT_INSTANCE_COUNT — the per-pod limiter divides configured limits by
  this. It MUST be the upper bound on live admin-api pods, else the fleet
  over-permits: with HPA on, that's maxReplicas (the limiter runs tighter below
  max, never looser); with HPA off, the static replica count.
*/}}
{{- define "streamscope.rateLimitInstanceCount" -}}
{{- if .Values.adminApi.autoscaling.enabled -}}
{{- .Values.adminApi.autoscaling.maxReplicas -}}
{{- else -}}
{{- .Values.adminApi.replicas -}}
{{- end -}}
{{- end -}}

{{/*
  Soft anti-affinity spreading a component's replicas across nodes — backs the
  HA claim so a single node loss can't take a whole tier down. Caller passes a
  dict with "component" + root context keys; explicit .Values.affinity wins.
*/}}
{{- define "streamscope.podAntiAffinity" -}}
preferredDuringSchedulingIgnoredDuringExecution:
  - weight: 100
    podAffinityTerm:
      topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
          {{- include "streamscope.selectorLabels" . | nindent 10 }}
{{- end -}}

{{/*
  A pod's securityContext: the one given (`ctx`), with the network settings
  `k8s install --unsafe-sysctls` sets (`stowage.sysctls`, empty without it)
  added to its own `sysctls`. A name both set takes the installer's value.
  Caller passes a dict with "root" + "ctx".
*/}}
{{- define "streamscope.podSecurityContext" -}}
{{- $ctx := deepCopy (.ctx | default dict) -}}
{{- with .root.Values.stowage.sysctls -}}
{{- $names := list -}}
{{- range . }}{{- $names = append $names .name -}}{{- end -}}
{{- $own := list -}}
{{- range ($ctx.sysctls | default list) }}{{- if not (has .name $names) }}{{- $own = append $own . -}}{{- end }}{{- end -}}
{{- $_ := set $ctx "sysctls" (concat $own .) -}}
{{- end -}}
{{- toYaml $ctx -}}
{{- end -}}
