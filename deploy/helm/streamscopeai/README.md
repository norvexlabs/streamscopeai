# Streamscope AI — Helm chart

The Kubernetes shape of Streamscope: a **horizontally-scaling wrapper over the same container
images** the Docker deployment and the VM appliance run. admin-api scales horizontally
(leader-elected workers coordinate through Postgres), and the proxy scales as a plain Deployment
because each replica takes a **distinct edge identity** under one shared edge token.

Canonical production shape: **managed Postgres outside the cluster**, **Ingress + cert-manager** for
TLS, and **autoscaling** proxy + admin-api. The chart runs no backup job and no disk-pressure purge:
on Kubernetes the database platform owns backup, failover, and elastic storage — the managed provider
with `external`, CloudNativePG with `cnpg` (its backups configured through `postgres.cnpg.backup`).

Operator-facing install and day-2 steps: [docs/OPERATOR_GUIDE.md § F](../../../docs/OPERATOR_GUIDE.md#f-kubernetes-deployment).

## Installed by `ssai-stow k8s`, never a bare `helm install`

The chart is published with each release and installed by the release's installer:

```bash
docker run --rm <registry>/streamscopeai-installer:latest > streamscopeai.sh
sh streamscopeai.sh k8s install --values my-values.yaml     # upgrade / rollback / status / reset-db / secrets rotate
```

`streamscopeai.sh` carries the installer, `ssai-stow`, and runs it with its arguments: `sh
streamscopeai.sh k8s …` is `ssai-stow k8s …`. `ssai-stow k8s` drives the operator's own `helm` (≥ 3.14) and `kubectl`. It:

- writes the Secret **`<release>-stowage`** — the generated secrets (`ENCRYPTION_KEY`,
  `AUTH_SECRET` with its `AUTH_SECRET_NEXT` / `AUTH_SECRET_PREVIOUS` rotation slots and
  `AUTH_SECRET_ACCEPTED`, whichever of the two holds a value,
  `INTERNAL_SERVICE_SECRET`, `EDGE_TOKEN`, `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`) and every
  Kubernetes input (`SETUP_ADMIN_EMAIL`, `TENANT_NAME` / `TENANT_SLUG` / `TENANT_ADMIN_EMAIL`, and with
  `postgres.mode=external` `MIGRATION_DATABASE_URL` / `DATABASE_URL`) — plus a pull Secret
  `<release>-stowage-pull` when the release registry needs a sign-in (the public release needs
  none);
- pulls the chart by digest and runs `helm upgrade --install --atomic --wait` with a values file of
  its own — `stowage: {registry, secret, pullSecret}` beside the `stowage.images` block `ship`
  appended to `values.yaml` — then the operator's `--values`.

The templates read only that: every image is `<stowage.registry>/<repository>@<digest>`
(`streamscope.image` in `_helpers.tpl`), every secret a per-key `secretKeyRef` of `stowage.secret`
(never `envFrom`), and the chart refuses to render without the `stowage` block.
`AUTH_SECRET_ACCEPTED` becomes admin-api's `AUTH_SECRET_SECONDARY`. The chart's own pods (a
CloudNativePG cluster's are the operator's) add `stowage.sysctls`, the network settings
`k8s install --unsafe-sysctls` sets (empty without it), to the `sysctls` their security context
already carries; a name both set takes the installer's value.

**Provisioning** is not a chart template: once helm has settled the release, `ssai-stow k8s`
runs the release's `provision` image — the same script Docker and the VM run as their provision
hook — as the Job `<release>-stowage`, with the inputs the spec's `hooks.provision.env` lists from
`stowage.secret`. What it returns (passwords, keys) is recorded in the Secret
`<release>-stowage-provision` and handed back on the next run. The chart gives it only
`templates/provision-env.yaml`, the ConfigMap `<release>-stowage-provision` (the in-cluster API URL
and the web grant), and admits its pod to admin-api in the NetworkPolicy by the labels the installer
sets (`app.kubernetes.io/component: stowage-provision`).

## Components

| Component  | Kind                | Scale         | Probes (liveness / readiness)        |
|------------|---------------------|---------------|--------------------------------------|
| admin-api  | Deployment + HPA*   | horizontal    | `/health` (200 always) / `/ready`    |
| proxy      | Deployment + HPA    | horizontal    | `/health` (200 always) / `/ready`    |
| admin-ui   | Deployment          | replicas      | `/api/live` / `/api/live`            |
| postgres   | external / cnpg / embedded(eval) | — | provider-specific                |

`/ready` is the gate that matters: admin-api reports `503` until it can serve the gateways'
configuration, and `503 MIGRATION_FAILED` on a degraded boot, so a bad migration never serves; the
proxy reports `503` until it holds a usable config snapshot. A `startupProbe → /ready` with a
generous `failureThreshold` covers the pre-bind migration window.

\* admin-api HPA is opt-in. `RATE_LIMIT_INSTANCE_COUNT` (the per-pod limiter divides by it) is wired
from `adminApi.autoscaling.maxReplicas` with the HPA on, else `adminApi.replicas`.

## Values that matter

Every key is commented in `values.yaml`; `deploy/helm/quickstart/values.example.yaml` is the
operator's `--values` starting point.

| Value | What it decides |
|---|---|
| `postgres.mode` | `external` (default; the two URLs from the Secret, `DB_MANAGE_APP_ROLE=false`), `embedded` (single-pod StatefulSet + PVC, eval only; URLs built from the generated passwords), `cnpg` (a CloudNativePG `Cluster`; both URLs built from the release's two passwords, which the cluster's roles take, no superuser) |
| `postgres.cnpg.backup`, `postgres.cnpg.recovery` | `cnpg` only: the Barman Cloud Plugin `ObjectStore` spec rendered as given, with the cluster's WAL archiver and a `ScheduledBackup` (`schedule`, `serverName`); `recovery` bootstraps the cluster from a store (`serverName` required, optional `recoveryTarget`) instead of `initdb`. The render fails without the plugin's resource, or when a restored cluster would archive into the folder it restores from |
| `postgres.manageAppRole` | override `DB_MANAGE_APP_ROLE` (default: true only for `embedded`) |
| `hostnames.{adminUi,proxy,adminApi}` | the Ingress hosts (`adminApi` empty: co-hosted behind the UI origin) |
| `ingress.*` | class, cert-manager issuer, `hsts`, `proxyTimeoutSeconds` (900: outlasts the gateway's longest capacity hold) |
| `adminApi.replicas`, `proxy.replicas`, `*.autoscaling.*`, `*.workerThreads` | scale and per-pod CPU sizing |
| `adminApi.authMode`, `headerAuth*` | proxy-authenticated mode; `headerAuthTrustedProxy` is required with `authMode: header` (render fails without it) |
| `metrics.*` | the dedicated metrics port (9464, `0` disables), `scrapeNamespaceSelector`, `serviceMonitor` |
| `networkPolicy.*` | opt-in default-deny posture, `ingressNamespace`, `extraEgress` (an extension served on a port other than 80/443, e.g. an in-cluster search or classifier service, needs its port here) |
| `imagePullSecrets` | extra pull Secrets, for a mirror |

For `postgres.mode=external`, the DBA's one-time grants (the migration role may be a non-superuser):

```sql
CREATE ROLE streamscope_app LOGIN PASSWORD '<strong>' NOBYPASSRLS;  -- runtime role
GRANT streamscope_app TO <migrator>;          -- MANDATORY: enables ALTER … OWNER TO streamscope_app
ALTER SCHEMA public OWNER TO <migrator>;       -- (or CREATE … WITH GRANT OPTION on public)
GRANT CREATE ON DATABASE <db> TO <migrator>;   -- install the trusted pg_trgm extension
```

## Security posture

Non-root (uid/gid 65532), no privilege escalation, all capabilities dropped, `seccomp=RuntimeDefault`,
`readOnlyRootFilesystem` with an `emptyDir` only where a container writes, and
`automountServiceAccountToken: false` on every workload. The NetworkPolicy (opt-in) admits proxy +
console only from the ingress namespace, admin-api only from proxy, console and the installer's provision Job,
embedded Postgres only from admin-api; egress is DNS + Postgres + web + `extraEgress`.

## Rendering locally

The chart refuses to render without the installer's `stowage` block, so a local render or lint
supplies a stand-in:

```bash
d=sha256:$(printf '0%.0s' $(seq 64))
cat > /tmp/stowage-values.yaml <<EOF
stowage:
  registry: registry.example.com/streamscope
  secret: streamscope-stowage
  images:
$(for k in admin-api proxy admin-ui provision postgres; do
    echo "    $k: { repository: streamscopeai-$k, digest: \"$d\" }"; done)
EOF
helm lint deploy/helm/streamscopeai -f /tmp/stowage-values.yaml
helm template streamscopeai deploy/helm/streamscopeai -f /tmp/stowage-values.yaml \
  --set postgres.mode=embedded \
  --set networkPolicy.enabled=true > /dev/null
```

A render proves the templates; only an install (`ssai-stow k8s install`) proves the pods
come up.
