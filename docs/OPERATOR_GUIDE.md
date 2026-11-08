# Operator Guide

Everything needed to **deploy, run, and operate the infrastructure** behind Streamscope AI —
install, networking, TLS, backups, recovery, and updates. Once the system is up, configuring the
product itself (tenants, providers, workspaces, users, policy) is the [Admin Guide](ADMIN_GUIDE.md),
done entirely through the web UI.

Streamscope installs in **three form factors**, all running the **same container images** and all
installed by the **same installer, `ssai-stow`** — pick the one that fits how you operate:

- **VM appliance** — a ready-to-boot disk image, self-contained (OS + apps + database in one box),
  with atomic A/B upgrades, a boot health gate and off-host backups. The turnkey path for on-prem,
  air-gapped, and regulated environments. Covered in sections **B–D**.
- **Kubernetes** — a Helm chart wrapping the same images, with a **managed Postgres** outside the
  cluster, horizontal autoscaling, and Ingress + cert-manager for TLS. The elastic path for teams
  already running Kubernetes. Covered in section **F**.
- **Docker** — one command on any machine that runs Docker, database included. The shortest path to
  a running system, and the one to start with if you are evaluating. Covered in section **G**.

Because all three shapes run the same containers, everything you configure later in the Admin Guide
is identical across them — the choice is purely operational. Installing builds nothing from source.

**Contents**
- [A. How Streamscope is delivered](#a-how-streamscope-is-delivered)
- [B. Install the VM appliance](#b-install-the-vm-appliance)
- [C. Per-platform install recipes](#c-per-platform-install-recipes)
- [D. Day-2 operations](#d-day-2-operations)
- [E. Settings & environment reference](#e-settings--environment-reference)
- [F. Kubernetes deployment](#f-kubernetes-deployment)
- [G. Docker deployment](#g-docker-deployment)
- [H. Serving your own models with vLLM](#h-serving-your-own-models-with-vllm)

Section A (how a release reaches you), the settings reference (E), section H (running your own
inference engine behind the gateway) and everything in the Admin Guide apply to all three shapes.

---

## A. How Streamscope is delivered

A release is published to the GitHub Container Registry, `ghcr.io/norvexlabs`, as one signed set:
the container images, the installer, the Helm chart, the VM's OS bundle and its disk images, all for
the same version (`v<version>`, never rewritten). Every package is public: nothing needs an account
or a sign-in to install.

In this guide `<registry>` stands for `ghcr.io/norvexlabs`, or for your own mirror of it (below).

### What you need

- **Docker** on the machine you install from — even for Kubernetes and the VM, because the installer
  itself is delivered as an image. Nothing else: no source tree, no language runtimes.
- **Access to `ghcr.io`** from that machine and from the hosts that run the install, or a mirror
  (below) for a site without internet.

### Getting the installer

```bash
docker run --rm <registry>/streamscopeai-installer:latest > streamscopeai.sh
sh streamscopeai.sh …                # Docker install; `k8s …` and `vm create …` for the other shapes
```

`streamscopeai.sh` is a small POSIX script carrying `ssai-stow`, which in turn carries the
release — its manifest, its deployment definition and the keys that sign it — so an install needs
nothing else. The script unpacks `ssai-stow` into a private directory, runs it and removes it.
A Docker install keeps its own copy (`<dir>/ssai-stow`) for day-2 work, the VM carries one in
its OS, and `ssai-stow script` prints the bootstrap script again, to copy an installer to
another host. Where this guide writes `ssai-stow k8s …`, `ssai-stow vm …` or
`ssai-stow mirror …` on your workstation, run it as `sh streamscopeai.sh k8s …` (and so on).

Every release the installer reads — an upgrade, a version you name — must be signed by a key it
trusts; an unsigned or foreign release is refused.

Each image, the installer, the OS bundle and each disk of a release carries an SBOM (SPDX), attested
with the release's signing key. An image's SBOM also lists what is compiled into it — the Rust
crates of each binary, the packages the console bundles — which no scan of the image itself finds. On your workstation, `ssai-stow audit [--version V] [--fail-on high]
[--json] [--db FILE]` checks those attestations and scans them for known vulnerabilities, printed by
severity, each with the file its package was found in where the SBOM records it; a package found in
two programs is two findings. `--db` gives the scanner's database to a machine that cannot fetch it.
`ssai-stow sbom export DIR [--version V]` writes the verified SBOMs as files for your own tools. Both read a mirror
with `--registry` (and `--registry-ca`), and a mirror export carries the SBOMs and the scanner.

### Sites without internet

A site without internet runs a registry of its own (a **mirror**), and each release crosses the gap
as one file:

```bash
# On a machine with internet:
ssai-stow mirror export [--channel stable] [--version V] [--output FILE] [--disks qcow2,ova|none] \
                        [--shapes docker,kubernetes,kairos]
# On the site, signed in to the mirror with `docker login`:
ssai-stow mirror import streamscopeai-<tag>.oci.tar --to <mirror>/streamscopeai [--registry-ca ca.pem]
```

The archive holds the release, its images, installer, chart, OS bundle and disk images, byte for
byte, so its signatures still verify from the mirror. It carries the channel's latest release unless
`--version` names another (to hold a site at one, or to cross a schema barrier one release at a
time); `--disks` limits the disk formats, and `--shapes` the shapes the site runs — leaving out
`kairos` leaves out the OS bundle and every disk, most of the archive's size. Then each shape
reads the mirror:

| Shape | Install from the mirror |
|---|---|
| Docker | `ssai-stow --registry <mirror>/streamscopeai --registry-ca ca.pem` |
| Kubernetes | `ssai-stow k8s install --image-registry <mirror>/streamscopeai --registry-ca ca.pem` |
| VM | `ssai-stow vm create --registry <mirror>/streamscopeai --registry-ca ca.pem` |

`--registry-ca` is the PEM of the certificate authority the mirror's certificate chains to
(certificates only). The installer records the mirror at the first install, and later upgrades and
`updates` look for new releases there; a newer release crosses the same way. A mirror that asks for
a sign-in is read with your own `docker login`. On Kubernetes the cluster's nodes pull
the images themselves, so they must already trust the mirror's CA, and you give the chart a pull
Secret for it (`imagePullSecrets` in your values).

---

## B. Install the VM appliance

### VM sizing

| | vCPU | RAM | Data disk space |
|---|---|---|---|
| **Minimum** | 2 | 4 GB | 20 GB |
| **Recommended** | 4 | 8 GB | 40 GB |

`vm create` sizes a new VM at the recommended size unless you give another, and refuses one under
the minimum.

**RAM** — 4 GB runs the gateway; 8 GB leaves headroom for load. The services use what the VM has:
at every boot the database, the gateway and the admin API are each given a share of its memory
(30 %, 20 % and 10 %, up to 16 GB, 8 GB and 4 GB), and the database sizes its cache from its share.
A VM given more memory uses it from its next boot.
Its network is tuned at each boot for its size and for the gateway's many connections (the
`network` profile).

**Disk** — the sizes above are the space for the appliance's data (the database, audit and session
history, the gateway's buffers and the bundled container images). The appliance also keeps **two OS
systems** (active and passive, for atomic A/B rollback) and a recovery system; `vm create` adds the
space they take to the disk it makes and prints both (`a 43 GiB disk (the OS 23 GiB, the app 20
GiB)`). Size up from the minimum with your retention window and request
volume; the appliance tightens retention on its own as the disk fills (see *Disk pressure* in § D).

### Prerequisites (operator workstation)

- **Docker**, to fetch the installer (§ A).
- An **SSH key pair**. Your public key is the only way into the VM: SSH is key-only and there is no
  password, on SSH or on the console. The VM's SSH allows at most 4 authentication tries and no port,
  agent or X11 forwarding: with an SSH agent holding more keys, connect with
  `ssh -i <key> -o IdentitiesOnly=yes`. A session that stops answering is dropped after 10 minutes.
- **DNS names** for the five routes the appliance serves over HTTPS (see *TLS modes*): the console,
  the API, the gateway, and the two metrics endpoints.
- For `--tls dns-cloudflare`: a **Cloudflare API token** with *Zone → DNS → Edit* on each name's zone.
- For automated creation on **TrueNAS**: [OpenTofu](https://opentofu.org) 1.8+ and a TrueNAS API key
  (see [section C](#c-per-platform-install-recipes)).

### Step 1 — Run the guided installer

```bash
sh streamscopeai.sh vm create --platform <platform>
```

It walks the whole preparation end-to-end, asking what it was not given as a flag:

1. **The platform** — `truenas`, `proxmox`, `libvirt`, `vmware`, `hyperv`, `azure`, `gcp` or `aws`
   (only the platforms the release publishes a disk for are offered). The platform decides the disk
   format and how the configuration reaches the VM.
2. **The machine** — host name, administrator user name and SSH public key, network (DHCP, or a
   static `--address A/P` with `--gateway` and `--dns`), the sources SSH accepts (`--ssh-allow`;
   without it a VM on AWS, Azure or Google Cloud accepts your workstation's public IPv4 address
   alone — looked up from an internet address service, and the run stops when it cannot be; SSH
   over IPv6 is refused — and a VM on
   the other platforms every source, with a warning) and the time zone (`--timezone`, default UTC).
   On a cloud, name the operators' addresses with `--ssh-allow` when yours changes (a dynamic or VPN
   address): SSH from any other is refused, which is the *Lost SSH* case of the recovery playbook.
3. **The product** — the TLS mode, the five domains, and the install questions: the platform
   administrator's email, the organisation to create and its administrator, and the addresses
   allowed to scrape metrics. Every answer is reviewed before anything is written.
4. **Downloads the disk image** for the platform and checks it against the release.
5. **Writes the VM's configuration** — a seed ISO (`<hostname>-seed.iso`) for hypervisors, or a
   user-data file (`<hostname>-user-data.yaml`) for clouds — and **prints the next steps for your
   platform**. On TrueNAS with OpenTofu it creates and starts the VM itself, then waits until the
   install has finished. It never replaces a seed it finds: to run it again for the same host
   name, move away the one an earlier run wrote.

**The VM's configuration carries no secret** — but for a one-time SSH host key (written readable by
you alone) whenever `vm create` sends something over SSH (`--secrets`, a secret input, a `byo`
certificate), which the VM stops serving once it is installed: keep the seed as private as the
key. Every secret — the encryption key, the signing secret,
the database passwords — is generated on the VM at its first install and never leaves it unless you
export it (see *Secrets & security model*). A secret input — a Cloudflare token — and a `byo`
certificate never enter the configuration either. Give them to `vm create` — a secret input in the
`--answers` file (`vm create` refuses one in `--set`), the certificate with
`--cert`/`--key`/`--ca` or the answers file's `tls` section — and they are checked before the VM
exists, the first boot waits for them, and they are sent over SSH to the first install, pinned to
the VM's one-time host key. With a VM you create by hand, `vm create` writes them to a private
`<hostname>.given` file beside the seed — it holds them in the clear — and prints the one command
that delivers them: run that one as printed, which pins the VM's one-time host key (kept in a
`.known_hosts` file beside it) and deletes both files once the install took them, rather than a
plain `ssh … install --given -`. Until you run it, `status` says the VM is not installed, and a
plain `install` is refused, naming `--given`; the file lost, `install --new-secrets` goes on
without it, given the certificate and secret inputs again by their flags (`--cert`, `--key`,
`--ca`, `--answers`). A boot after the install began retires the one-time key, and ssh then refuses
it: check the VM's own key on its console, and run the printed command without its host-key
options. `--secrets` takes
no `byo` certificate: it restores an install (the Cloudflare token comes back with the exported
secrets), so create a `byo` VM with `--secrets` in another mode and move it to `byo` by a re-run.
One not given is named at the end, for you to give over SSH:

```bash
ssh -t <user>@<vm> sudo ssai-stow install             # asks for what is still due, then installs
```

**The `vm create` flags** (each is asked on a terminal when not given):

| Flag | Description |
|---|---|
| `--platform P` | The target platform (above). |
| `--out DIR` | Where the disk and the seed are written (default: the current directory). |
| `--hostname H` | The VM's host name (default `streamscopeai`). |
| `--user U` / `--ssh-key FILE` | The administrator and their SSH public key (default your user name and `~/.ssh/id_ed25519.pub`, `id_ecdsa.pub` or `id_rsa.pub`). The administrator has passwordless `sudo`. The VM allows 4 authentication tries: keep the private key beside the `.pub`, which `vm create` then connects with alone, or an SSH agent holding at most 4 keys. |
| `--network dhcp\|static` `--address A/P` `--gateway G` `--dns D,…` | The install-time network (IPv4). Change it later without reinstalling — see *Changing the network settings*. |
| `--ipv6` [`--address6 A/P` [`--gateway6 G`]] | Turn IPv6 on: the VM takes its addresses from router advertisements (and DHCPv6 with `--network dhcp`), plus an optional static IPv6 address beside them and its gateway (`--gateway6` needs `--address6`). Without `--ipv6` the VM has no IPv6 at all. |
| `--ssh-allow CIDR,…` | The sources SSH accepts (IPv4 or IPv6). Leave out the address you reach the VM from and you lock yourself out. Without it, a VM on AWS, Azure or Google Cloud accepts SSH from your workstation's public address alone (`0.0.0.0/0,::/0` accepts every source); on the other platforms, from every source. |
| `--timezone ZONE` | IANA zone name, e.g. `Europe/Paris`. |
| `--tls MODE` `--domains route=host,…` | How the appliance serves (see *TLS modes*). |
| `--cert FILE` `--key FILE` `--ca FILE` | The `byo` certificate, its key and its issuing CA, sent over SSH to the first install. Give `--ca` for a private CA: without it the chain is checked against your workstation's trusted CAs. |
| `--http-port N` `--https-port N` | Move the front's ports. |
| `--set KEY=VALUE`, `--answers FILE` | The install answers and the advanced settings of § E. `--answers` is a YAML map, `KEY: value`, and may carry the front's TLS settings in a `tls` section (`mode`, `cert`, `key`, `ca`, paths relative to the file); a flag wins over the file. |
| `--secrets FILE` | A decrypted secrets export: rebuild a VM with the secrets of one that was lost (see *Recovery playbook*). The secrets go only to the VM `vm create` made: until its install, the VM serves a one-time SSH host key its seed carries, and `vm create` refuses any other. It then records the VM's own key and prints its fingerprint; without automated creation, it prints the one-time key's fingerprint for you to check before you send the secrets. |
| `--registry PREFIX` `--registry-ca FILE` | Install from a mirror (§ A). |
| `--tune-profile default\|network` | The VM's network tuning (default `network`, for the gateway's many connections). On an installed VM, `sudo ssai-stow install --tune-profile P` changes it, and `--tune-profile release` returns to the release's own. |
| `--no-input` | Ask nothing: flags and defaults decide. |

### Step 2 — Boot the VM

Follow the steps `vm create` printed (more per platform in [section C](#c-per-platform-install-recipes)):
import the disk, attach the seed ISO as a CD-ROM (or put the user-data file in the cloud's user-data
field) and start the VM.

On first boot the VM runs its recovery system, installs itself, resets and reboots into the active
system, then installs Streamscope from the images the OS carries — nothing is pulled — and runs the
provisioning: the platform administrator, the organisation and its administrator. Allow a few
minutes before verifying.

The VM's **IPv4 address is shown on the console** above the login prompt, with the SSH command to
connect (and, with `--ipv6`, its IPv6 address too), so you can read a DHCP-assigned address without
logging in.

> **Do not attach a QXL display adapter.** QXL hangs the appliance's shutdown, so the VM stops
> responding partway through a reboot and never completes an update. VMware's default adapter is
> fine, and so are `virtio-gpu`, `bochs`/`stdvga` or `cirrus` on QEMU. On TrueNAS give the VM no
> Display device; on Proxmox keep the default `std`; with `virt-install` / virt-manager pass
> `--video virtio`, because their SPICE default is QXL.

### Verification

| # | Check | Pass criteria |
|---|---|---|
| 1 | `ssh <user>@<vm> ssai-stow status` | The OS and the installed release on the same version, its channel, every service `running`, no `not finished` line |
| 2 | `ssh <user>@<vm> ssai-stow health` | `ready` |
| 3 | `ssh <user>@<vm> ssai-stow ps` | Every service up and healthy |
| 4 | `curl -I https://<console-host>/` | a redirect to the portal, valid certificate (or the local CA with `internal`) |
| 5 | Browser → `https://<console-host>/admin` → sign in | Lands on the dashboard |

The accounts provisioning created and their passwords are in `/usr/local/streamscopeai/credentials.txt`
on the VM (readable by root only): `ssh <user>@<vm> sudo cat /usr/local/streamscopeai/credentials.txt`.
Copy them to your own secret store, then delete the file.

The VM is up. The organisation administrator signs in at `https://<console-host>/admin`, the
platform administrator at `https://<console-host>/system`, and users reach their portal at the
host's root. The platform reaches nothing on your private network until the platform administrator
lists it under **Settings → Egress** (a model server on the LAN, internal MCP servers, the extensions —
§ E, *Internal-egress posture*). Identity providers, more providers and users are configured
through the UI — continue in the [Admin Guide](ADMIN_GUIDE.md).

### Advanced & reference

#### Secrets & security model

- **Secrets are generated on the VM.** The first install generates the encryption key, the signing
  secret, the internal service secret, the gateway token and the database passwords, and keeps them
  on the VM's persistent partition, readable by root only. Neither the disk image nor the VM's
  configuration carries any of them.

- **Each service gets only the secrets it uses.** Only the admin API holds the full set. The
  **gateway** gets the data-encryption key and its gateway token, the **console** the internal
  service credential it needs to complete a sign-in, and the **TLS front end** the Cloudflare token,
  which it reads only with `dns-cloudflare`. Nothing here is configurable and it needs no operator
  action; it means a compromise of the gateway, the console or the TLS front end does not expose the
  database passwords or the signing secret.

- **App data at rest.** `ENCRYPTION_KEY` encrypts upstream provider credentials in Postgres
  (AES-256-GCM). It is permanent: a database restored without it cannot decrypt them.

- **Export the secrets for disaster recovery.** The VM holds the only copy until you export one:

  ```bash
  ssh <user>@<vm> ssai-stow secrets export --recipient age1… -o - > streamscope-secrets.age
  ```

  The file is encrypted to the age public keys you name (1 to 16, repeat `--recipient`); no private
  key is needed on the VM. Keep it **off the VM**, beside the age private key that decrypts it — it is
  what lets a rebuilt VM read the data a backup restores (see *Recovery playbook*).

- **Backups are one-way.** Backups are encrypted to age **public** keys; the VM never holds a
  private key, so a compromised VM cannot decrypt its own past backups (see *Backup & restore*).

#### Rotating `AUTH_SECRET`

`AUTH_SECRET` signs every browser session, portal session, CLI token, and MCP OAuth token.
**Only the admin API holds it** — the gateway is given public verification keys instead, so
there is nothing to rotate there.

Each token records which secret signed it, and Streamscope can hold two at once: the one it
signs with, plus a second it will only ever *verify* against. The installer rotates it in three
passes, each of which restarts the services that read it:

```bash
ssai-stow secrets rotate AUTH_SECRET --stage           # 1. a new secret, accepted but signing nothing yet
ssai-stow secrets rotate AUTH_SECRET                   # 2. swap: new tokens sign with the new secret; old ones still verify
ssai-stow secrets rotate AUTH_SECRET --finish          # 3. retire the old secret
```

On the VM run them over SSH; on Docker add `--dir <dir>`; on Kubernetes use
`ssai-stow k8s secrets rotate AUTH_SECRET …`, which restarts the pods one at a time. Nobody is
signed out by the first two passes: between any two, every service accepts tokens signed by either
secret, so a replica that has restarted and one that has not are interchangeable.

Run `--finish` once every token issued under the old secret has expired — the longest-lived is the
30-day OAuth refresh token, so wait 30 days to be certain, or accept a shorter window and sign the
stragglers out.

**Retiring a secret takes effect through config sync, not through a restart.** The gateway
learns which keys to accept from the configuration the admin API pushes it, so retiring the old
secret stops MCP OAuth tokens signed by it only once every gateway has picked up the new
configuration — normally a second or two. Watch the sync indicator in the console if you need to be
sure. Browser, portal and CLI sessions are checked by the admin API itself and stop the moment it
restarts.

#### TLS modes

The appliance and the Docker deployment serve through a built-in TLS front end. `--tls` picks where
its certificates come from; renewals are automatic. Each route has its own hostname:

| Route | Serves | Domain input |
|---|---|---|
| `console` | the admin console and the user portal | `ADMIN_DOMAIN` |
| `api` | the admin API (machine-facing: CLI, automation, OAuth) | `API_DOMAIN` |
| `gateway` | the LLM / MCP / A2A gateway | `PROXY_DOMAIN` |
| `metrics-api` | the admin API's Prometheus metrics | `METRICS_API_DOMAIN` |
| `metrics-gateway` | the gateway's Prometheus metrics | `METRICS_GATEWAY_DOMAIN` |

Give them with `--domains console=admin.example.com,api=api.example.com,gateway=gateway.example.com,metrics-api=metrics-api.example.com,metrics-gateway=metrics-gw.example.com`
(or the domain inputs with `--set`). Use separate names: the console and the API must be different
origins — command-line tools and integrations discover the API address from the console.

| Mode | Certificate source | Required input |
|---|---|---|
| `acme` | Let's Encrypt, HTTP-01 / TLS-ALPN | ports 80 and 443 reachable from the internet; optional `--set STOWAGE_ACME_EMAIL=ops@example.com` for expiry notices |
| `dns-cloudflare` | Let's Encrypt, DNS-01 through Cloudflare | `STOWAGE_CLOUDFLARE_API_TOKEN` (secret; *Zone → DNS → Edit* on each zone). Works even when 80/443 are not public |
| `byo` | your certificate | `--cert FILE --key FILE` (PEM, covering every domain, unexpired); optional `--ca FILE`, the issuing CA — see CLI trust below. On the VM, `vm create` takes them too and sends them over SSH to the first install (below) |
| `internal` | the front end's own local CA | none — smoke tests and evaluation; browsers warn |
| `none` | plain HTTP on a loopback address | Docker only (§ G) |

Every HTTPS route sends `Strict-Transport-Security`, except with `internal`, where a pin would make
the self-signed warning impossible to click through. With `byo` and a **private** CA, make sure every
browser trusts that CA before the first visit.

**Changing the mode or the certificate later** is a re-run of the install (on the VM over SSH, as
`sudo ssai-stow install …`; on Docker as § G describes):

```bash
sudo ssai-stow install --tls byo --cert cert.pem --key key.pem [--ca ca.pem]          # move to your own certificate
sudo ssai-stow install --cert new-cert.pem --key new-key.pem                          # renew a byo certificate
sudo ssai-stow install --given - < token.yaml                                           # rotate the Cloudflare token
sudo ssai-stow install --tls dns-cloudflare --given - < token.yaml                     # move to DNS-01
```

`token.yaml` keeps the token off the command line and out of the shell history: `project:
streamscopeai` and `inputs:` holding `STOWAGE_CLOUDFLARE_API_TOKEN: <token>`; delete it once given.

`--tls` moves between `acme`, `dns-cloudflare`, `byo` and `internal`. A VM can start in `byo`:
`vm create --tls byo --cert FILE --key FILE [--ca FILE]` checks the certificate before the VM exists,
and sends it over SSH to the first install, pinned to the VM's one-time host key — never in its
configuration. A `byo` VM rebuilt with `--secrets` (*Recovery playbook*) is created in another
mode and moved to `byo` by a re-run.

> **CLI trust for private CAs.** When TLS is publicly trusted (`acme`/`dns-cloudflare`), the
> `ssai` CLI installer needs no extra setup. When the gateway uses a **private** CA — the
> local CA of `internal`, or a `byo` certificate signed by a private root — the CLI installer fetches
> that root from the API, shows its subject/serial/SHA-256 fingerprint for you to validate, and
> installs it into the OS trust store (trust-on-first-use). For `internal` this is automatic. For
> `byo`, give the issuing root with `--ca FILE` so it can be published; without it, a runner that
> doesn't already trust your enterprise root can't install the CLI over TLS (the installer refuses
> rather than trusting a leaf certificate).

> **`internal`-mode trust collision (`SEC_ERROR_BAD_SIGNATURE`).** The local CA uses a fixed generic
> subject (`Caddy Local Authority - … Root`) — only the key differs per instance. If your browser
> already trusts a *different* such CA (typically from local development), it matches the VM's
> certificate to that stale root by name, verifies with the wrong key, and hard-fails with
> `SEC_ERROR_BAD_SIGNATURE` — no click-through. Fix: remove every **"Caddy Local Authority"** entry
> from the browser's trusted authorities (Firefox: Settings → Privacy & Security → Certificates →
> View Certificates → Authorities → Delete/Distrust), then reload and accept the warning, or import
> this install's root, which `https://<api-host>/api/v1/cli/ca` serves. For real browser access use
> `byo` or `acme`/`dns-cloudflare` instead.

#### First-boot lifecycle

1. The VM reads its configuration from the seed ISO (or the cloud's user-data) at first boot: host
   name, administrator and SSH key, network, SSH allowlist, time zone and the install answers.
2. Its recovery system installs the OS, resets and reboots into the active system; the persistent
   data partition grows to fill the attached disk.
3. The boot loads the bundled images and makes the first install from the answers — or, when
   `vm create` sends something over SSH, the install that delivery runs: generates the
   secrets, starts the stack and runs provisioning. `ssai-stow status` says `not finished` until
   that is done, and names the command that runs it again if it failed.
4. A health gate judges every boot: the install must be up, on the release the OS carries, and ready.

Persistent state (the database, the gateway's buffers, the front end's certificates, the install's
settings) lives on the persistent partition and survives reboots **and** A/B OS upgrades. The VM's
firewall drops everything except SSH (from `--ssh-allow`) and the front's HTTP/HTTPS ports.

#### MAC pinning

Most hypervisors mint a random MAC per VM. Pin the NIC MAC and reserve the matching DHCP lease so a
re-created VM keeps the same IP (handy when DNS records point at the VM). A TrueNAS VM made by
`vm create --create opentofu` already gets a MAC derived from its name.

---

## C. Per-platform install recipes

The disk image is generic — one image per format serves every install; what differs per platform is
the format and how the VM's configuration reaches it. `vm create` picks both from `--platform` and
prints the remaining steps:

| `--platform` | Disk | Configuration |
|---|---|---|
| `truenas`, `proxmox`, `libvirt` | `qcow2` (else `raw`) | `<hostname>-seed.iso`, attached as a CD-ROM |
| `vmware` | `ova` | `<hostname>-seed.iso`, attached as a CD-ROM |
| `hyperv` | `vhd` | `<hostname>-seed.iso`, attached as a CD-ROM |
| `azure` | `vhd` | `<hostname>-user-data.yaml`, as custom data |
| `gcp` | `gce` | `<hostname>-user-data.yaml`, as `user-data` metadata |
| `aws` | `raw` | `<hostname>-user-data.yaml`, as user data |

Give the VM UEFI firmware, a VirtIO (or the platform's default) NIC and no QXL display (see Step 2).

### TrueNAS (automated, OpenTofu)

On TrueNAS `vm create` can create the VM itself:

```bash
export TRUENAS_URL=https://truenas.example.com TRUENAS_API_KEY=…   # TRUENAS_INSECURE_SKIP_VERIFY=1 for a self-signed host
sh streamscopeai.sh vm create --platform truenas --create opentofu \
  --hostname streamscopeai --pool tank --dataset vms --bridge br0 \
  --tls dns-cloudflare --domains console=…,api=…,gateway=…,metrics-api=…,metrics-gateway=… \
  --ssh-allow 192.168.1.0/24 --timezone Europe/Paris
```

Its size is the recommended VM unless `--cpus`, `--memory` (MiB) or `--disk` (GiB, the data space;
the OS systems' space is added) say otherwise (see *VM sizing*). It uploads the disk and the seed, creates the VM (UEFI, autostart, a MAC derived from its name),
starts it, and waits (`--wait`, default 20m) until `ssai-stow status` on the VM reports the
install finished. The API key is read from the environment only and never written to a file. Remove
such a VM, its disk and its uploads with `ssai-stow vm destroy <hostname>`.

### Other hypervisors and clouds

Import the disk `vm create` downloaded (`streamscope-<version>.<format>`) as the VM's boot disk,
attach the seed ISO as a CD-ROM on first boot (or pass the user-data file on a cloud), and start it.
The printed steps name the files. On VMware, import the OVA (it carries UEFI firmware and the VM's
hardware), then add the CD-ROM. With `virt-install` pass `--video virtio` (its default is QXL).

---

## D. Day-2 operations

Every operation on a running VM goes through **`ssai-stow`** over SSH as the administrator
`vm create` made — or through the console's **Appliance** page. The verbs that change the install
itself (`install`) need `sudo`; the rest do not.

### Updates & rollback

> **From the console (super-admin).** The **Platform → Appliance** page operates the appliance
> from the web: view the running version, services, and storage; **restart**, **shut down**,
> **upgrade** (with release notes and live progress), **roll back**, and check for new versions.
> A notification is raised automatically when a newer version is available. The same page changes the
> appliance's **network settings** and its **backups**. The page is shown only on the VM appliance.
> The SSH path below is equivalent and remains the path to use when the console is unavailable.

Updates are atomic A/B swaps of the whole OS + apps:

```bash
ssh <user>@<vm> ssai-stow updates                       # is a newer release out? with its changelog
ssh -t <user>@<vm> ssai-stow upgrade                    # show it, confirm, back up, write, reboot
ssh -t <user>@<vm> ssai-stow rollback                   # back to the release the last upgrade replaced
```

`upgrade` takes the latest release (`--version V` for another). **Read the changelog of every release
between yours and the target**: an entry marked **BREAKING** names what you must do around the
upgrade (a removed install input, a list to fill in, an address that moved). It shows the release and its changelog and
asks to confirm (`--yes` skips the question and is required without a terminal). It then takes a
backup when backups are configured (`--skip-backup`: none, over SSH only — an upgrade from the console always takes it), writes the new system to the passive
slot — **none of that interrupts service** — and reboots after 30 seconds (`--no-reboot`: the next
reboot activates it). That reboot is the upgrade's only downtime. On the way up, the boot dumps the
database before the new release migrates it. The command ends at the reboot it schedules: after it,
`ssai-stow status` and `ssai-stow events` tell how it went.

**The health gate.** After an upgrade, the first boot of the new system is on trial: unless the
install is up, on the new release and ready within 10 minutes, the gate reboots and the VM falls back
to the passive system, which goes back to the previous release. `status` then shows the failed boot
and why, diagnostics are kept on the VM, and `updates` no longer offers the release that failed.

**Rolling back after an upgrade that changed the database.** The previous release reads past
database changes it does not know, so `rollback` works after such an upgrade too. It checks first,
and refuses — naming the reason and the database dump taken before the upgrade — when the database
carries a change older releases cannot run on (such a release says so in its changelog). Going back
past one means restoring the backup taken before the upgrade (see *Backup & restore*). The health gate
asks the same question before it falls back on its own: when going back is refused, it keeps the new
system running, and `status` says `kept on this system, as going back is refused: …`.

> **Rolling back across a release that changes session tokens signs everyone out.** The
> previous version cannot read tokens the newer one issued, so users sign in again after the
> rollback. Releases with this effect say so in the changelog; the rollback is otherwise unaffected.
>
> **Upgrading can strand the audit a gateway has not yet delivered.** A release that changes how a
> gateway buffers audit records says so in its changelog. Records the gateway still held undelivered
> when it moves onto such a release — including any buffered while the upgrade is under way — are
> not delivered by it: they stay on the gateway's disk and reach the console only if the gateway is
> rolled back (or the health gate falls back), and the gateway reappears in the console as a new
> instance. Before such an upgrade, check that the platform **Overview** shows no audit records
> buffered on gateways, with the console up. The same holds for a Docker install; a Kubernetes
> gateway pod's buffer is its temporary storage, which every rollout replaces (see § F).

`upgrade`, `rollback`, backups, restores and secret rotations run on the appliance as jobs, one at a
time: they keep going if the SSH session drops, and `ssai-stow events [--follow]` shows the
appliance's journal of jobs, reboots and the health gate's verdicts.

### Automating the admin API (operator key)

Scripted provisioning (creating tenants, seeding providers, wiring OIDC) should
not run as a person. Instead, use a long-lived **operator key** — an admin
automation key (`ak-…`) owned by a *service account* in the system tenant, with
**operator** scope — and let your automation hold that. This is product behaviour:
it works identically on every deployment shape.

Provisioning already minted one: it is `OPERATOR_AK` in `credentials.txt` on the VM and Docker,
and in the Secret `<release>-stowage-provision` on Kubernetes. Otherwise, bootstrap it once, then
drop the human credential:

1. Sign in to the admin API with the platform administrator to obtain a session token.
2. With that token, create a service account in the system tenant (the admin
   console's **Auth → Service Accounts** tab) and mint an `ak-…` key on it with
   **operator** scope (the **Keys** page, or the admin API directly).
3. Store the `ak-…` key in your own secret store. Discard the human session token.

From then on, every automated call uses `Authorization: Bearer ak-…` — the key
identifies its own tenant, so no tenant header is needed and no person's password
is in the pipeline. The key is
revocable and every action it takes is attributed to it in the admin audit log,
so a leaked operator key is contained by revoking it (and minting a fresh one),
never by rotating a shared human password. Scope a *non*-operator key to a single
tenant (read-only or admin) when the automation only manages one tenant.

### Backup & restore

Postgres is the only state that cannot rebuild itself — certificates, the gateway's buffers,
container images and seeded configuration all do. A backup is a `pg_dump` encrypted with age as it
streams and uploaded with rclone to a destination off the VM; nothing is written to the VM's disk.

**The appliance is a single node: its database has no standby and no failover.** Its answer to a
lost database or a lost VM is this backup and the *Recovery playbook* below (scenario 6), so what
you can lose is bounded by the backup schedule (your RPO), and how long a restore takes is what the
restore drill measures (your RTO). While the database is down the gateway keeps serving the traffic
it already knows and holds its audit records on the VM's disk until the database is back. A
deployment that must survive the loss of a node runs on Kubernetes with a managed database or
CloudNativePG (§ F, *Backups, HA, and scaling*).

**Profiles**: `full` (every table, every row — the one a restore loads) or `config` (every table's
structure and the settings — tenants, users, keys, providers, routes, policy — without the audit,
session and conversation rows; small enough to take often).

**Set it up over SSH; adjust it from the console.** The rclone config (the destination's remotes
and their credentials) is yours alone, given over SSH: the appliance runs rclone as root, and
rclone's options can name programs it runs, so the console can neither save one nor test with one.
Once you have saved it, the **Appliance → Backup** tab (super-admin) can move the **destination**
to another remote it defines and change the **encryption keys**, **schedule**, **profile** and
**retention**; **Test** tries the saved settings, or those in the form, over your rclone config,
against the destination without saving them; **Run now** takes a backup. To keep every setting yours alone,
`ssh <user>@<vm> ssai-stow backup config --lock`: the console then still shows them, tests the
saved ones and runs a backup, but cannot change them (`--unlock` gives them back). Each change the
console makes is recorded in `ssai-stow events`. The appliance runs only an rclone config
you saved over SSH (`backup config --rclone-config`).

**The rclone config** is an `rclone.conf` made on your workstation with `rclone config` (any rclone
backend: S3, MinIO, Backblaze B2, Wasabi, SFTP, pCloud…; [rclone's documentation](https://rclone.org/docs/)).
Each `[section]` is a remote; `--destination` is `<remote>:<bucket>/<path>`, the part before the
colon one of its sections' names. For example, for an S3-compatible bucket:

```ini
[backup]
type = s3
provider = Wasabi
access_key_id = <key>
secret_access_key = <secret>
endpoint = s3.us-west-1.wasabisys.com
```

Over SSH:

```bash
age-keygen -o backup.key               # on your workstation; the private key never goes to the VM
age-keygen -y backup.key               # → age1…, the recipient

ssh <user>@<vm> ssai-stow backup config --destination backup:my-bucket/streamscope \
    --rclone-config - --recipient age1… [--retention-days 30] [--schedule '*-*-* 03:00:00 UTC'] \
    [--profile full] < rclone.conf
ssh <user>@<vm> ssai-stow backup verify                 # write a probe file to the destination
ssh <user>@<vm> ssai-stow backup run                    # back up now, and wait for it
ssh <user>@<vm> ssai-stow backup status                 # the settings, the next and the last backup
ssh <user>@<vm> ssai-stow backup list                   # the destination's backups
```

The defaults are a daily backup at 03:00 UTC (within a 15-minute window; one missed while the VM was
off runs when it is back), kept 30 days (`0` keeps every one). `--recipient` takes 1 to 16 age public
keys; any one's private key decrypts. `backup verify --destination … --rclone-config … --recipient …`
tries settings without saving them. Each backup is named
`streamscope-<profile>-<UTC time>-<version>-r<revision>.pgdump.age`.

> **Protect the backup bucket.** The destination credentials live on the appliance, so use a
> **versioned / immutable** bucket (S3 Object Lock, B2 lifecycle) and a **least-privilege**
> (write, no-delete) key, and keep a copy of the destination credentials off-host alongside the
> age key and the secrets export for a total-loss rebuild.

**Restore** replaces the database with a `full` backup:

```bash
ssh -t <user>@<vm> ssai-stow restore <object> --identity - < backup.key
```

It asks to confirm, stops every service but the database, loads the backup into a database of its
own beside the current one, and swaps the two only once the load succeeded — a restore that fails
leaves the database as it was. Then the stack comes back and provisioning runs on the restored data.
A backup restores onto **the release it was taken from**: restore before upgrading, or roll back
first. A `config` backup is refused (restoring it would drop every row it left out).

**Restore drill** (monthly — an untested backup is a broken backup): build a scratch VM from the
secrets export (*Recovery playbook*, scenario 6), restore the latest backup onto it and sanity-check
it. Record the wall-clock (your RTO) and the schedule cadence (your RPO).

### Disk pressure

The appliance checks its data partition every 10 minutes. At **75 %** it asks the admin API to
tighten retention to 15 days of history (unless retention is already shorter), at **90 %** down to the
7-day floor, and the console's login screen says so until use drops below it. `ssai-stow status`
shows the current use and the last request. History is stored in weekly blocks, so a tightened
retention frees its disk within a week. When the disk keeps filling, enlarge it on the hypervisor
or shorten retention in the console.

### Recovery playbook (appliance)

Scenarios from least to most severe:

1. **An update broke the VM** — the health gate falls back to the previous release within 10 minutes
   (*Updates & rollback*); `ssai-stow status` shows the failed boot, why, and where its
   diagnostics are kept. If it didn't fire: `ssai-stow rollback`.

   The gate does **not** fall back to a release that could not start against the database (a change
   older releases cannot run on came with the upgrade): it keeps the new system running and says
   why in `status`. Recovery is then yours, from the backup taken before the upgrade.
2. **Migration failed at boot** — admin-api does not exit on a migration error; it reports
   **not ready** and answers HTTP 503 `{"code":"MIGRATION_FAILED",...}` on every request that
   needs the database, so read the reason with `ssai-stow health` and `ssai-stow logs
   admin-api` (the public URLs stay down meanwhile). The database is left at the previous version as
   if the migration never ran. **Default: `ssai-stow rollback`** (safe — the old release knows
   the old schema). Or fix forward with a corrected release, or (last resort, with a verified off-VM
   backup) `reset-db` and restore.

   **A backup restores onto the release it was taken from, not onto a newer one.** The dump carries
   the schema *and* the record of which migrations produced it, so restoring onto another release is
   refused. Roll the OS back first, then restore.
3. **The front end can't get a certificate** — with `dns-cloudflare`, usually a token without
   *Zone → DNS → Edit* on the zone: give a new one with `sudo ssai-stow install --given - < token.yaml`
   (*TLS modes*). With `acme`, ports 80/443 must reach the VM and DNS must
   point at it. Let's Encrypt retries on a backoff.
4. **Lost SSH** — SSH is key-only and there is no password anywhere, so a lost key or an
   `--ssh-allow` that leaves you out is not repairable from inside: rebuild the VM from the secrets
   export and the latest backup (scenario 6). Keep a second administrator key somewhere safe.
5. **`ssai-stow` cannot reach the appliance's daemon** — restart the VM from your hypervisor's
   management interface. It is safe: the data, the install's settings and the certificates survive,
   and the boot finishes any job a reboot stopped.
6. **VM destroyed** — on a new VM made with the **exported secrets**, the restored data decrypts as
   before (upstream credentials, keys). `vm create` never replaces a seed it finds: run it from
   another directory (or `--out`), or move away the lost VM's seed first:

   ```bash
   age --decrypt -i secrets.key streamscope-secrets.age > secrets.yaml
   sh streamscopeai.sh vm create --secrets secrets.yaml …     # same release as the backup; not --tls byo
   ssh <user>@<vm> sudo ssai-stow install --given - < byo.yaml   # if it served byo: project, tls of cert and key as PEM (§ D)
   ssh <user>@<vm> ssai-stow backup config --destination … --rclone-config - --recipient age1… < rclone.conf
   ssh <user>@<vm> ssai-stow backup list
   ssh -t <user>@<vm> ssai-stow restore <object> --identity - < backup.key
   ```

   The new VM starts unprovisioned and says so in `status` (`not provisioned: a backup … is
   awaited`) until the restore loads the data, so nothing is created on the empty database. Restore
   before flipping DNS, verify, then flip. Without backups **and** the secrets export, you
   re-provision from scratch and audit history is lost — which is why exporting the secrets and
   running off-VM backups is non-negotiable.

### `ssai-stow` reference

On the VM (over SSH):

| Command | Does |
|---|---|
| `ssai-stow status [--json]` | The release and channel, the install's state, each route's URL, the advanced settings in effect, the system booted (active / passive / recovery), the last failed boot, the disk and its pressure, the services |
| `ssai-stow health [--json]` | Ready, or why not — the health gate's check, from inside the VM, even when the public URLs are down |
| `ssai-stow ps [--json]` | The services, their state and health; a service that is down is named with its exit code, the signal, whether its memory limit killed it, and that limit (`status` says the same) |
| `ssai-stow logs <service> [--tail N]` | A service's last lines (default 200, at most 5000) |
| `ssai-stow restart \| stop \| start <service>` | One service |
| `ssai-stow events [--after N] [--follow]` | The appliance's journal: jobs, reboots, boots, the health gate's verdicts, the backup settings the console changed |
| `ssai-stow updates [--channel C] [--version V]` | A newer release, with its changelog |
| `ssai-stow upgrade [--yes] [--channel C] [--version V] [--no-reboot] [--skip-backup]` | Back up, write the passive slot, reboot into it after 30 s |
| `ssai-stow rollback [--yes]` | Reboot into the passive system: back to the release the last upgrade replaced |
| `ssai-stow reboot \| shutdown [--drain-secs N]` | Drain (default 30 s, at most 600), then reboot / power off |
| `ssai-stow backup config \| run \| status \| list \| verify` | Backups (see *Backup & restore*); `backup config --lock` / `--unlock` keeps the settings from the console or gives them back |
| `ssai-stow restore <object> [--identity FILE\|-]` | Load a backup into the database |
| `ssai-stow secrets export --recipient age1… [-o FILE\|-]` | The install's secrets, encrypted, for disaster recovery |
| `ssai-stow secrets rotate AUTH_SECRET [--stage \| --finish]` | Rotate the signing secret (see *Rotating `AUTH_SECRET`*) |
| `ssai-stow network [set \| confirm \| revert \| reset]` | The network settings (see below) |
| `ssai-stow provision [--set KEY=VALUE]…` | Run provisioning again (idempotent); `--set` corrects a value it recorded (§ E) |
| `sudo ssai-stow install [--set KEY=VALUE]… [--tls …] [--domains …] [--cert … --key …]` | Change the install's settings (see below); on a VM without an install, make it |
| `sudo ssai-stow install --given FILE\|-` | The same from a YAML file — `project: streamscopeai`, `inputs` of `KEY: value`, `tls` of `cert`, `key`, `ca` as PEM — read from a file or standard input, keeping a secret off the command line; how `vm create`'s `.given` file is delivered. The Docker install takes it too, and `k8s install` / `k8s upgrade` (without `tls`) |
| `ssai-stow reset-db [--yes] [--no-provision]` | **Destructive.** Wipe the database and the gateway's buffers (certificates kept), start again as first installed, with new passwords. Not a routine operation |

`--yes` skips a confirmation and is required without a terminal.

### Changing the install settings

The answers given at install, the domains, the TLS mode and the advanced settings of § E are changed
by running the install again over SSH:

```bash
ssh -t <user>@<vm> sudo ssai-stow install --set API_DOCS_PUBLIC=false
ssh -t <user>@<vm> sudo ssai-stow install --set METRICS_ALLOW=10.0.0.0/8
ssh -t <user>@<vm> sudo ssai-stow install --domains console=admin.new.example.com
```

It changes what it is given, and only that, logs each change, then brings the stack up again and
runs provisioning. An advanced setting given empty (`--set RUST_LOG=`) goes back to its default.
`ssai-stow status` lists every advanced setting in effect. The network settings and the backups
are separate (below, and *Backup & restore*): an install re-run never changes them.

### Changing the network settings

The address, gateway and DNS servers supplied at `vm create` are the appliance's **starting**
configuration, not a fixed one. Change them on a running VM from the console (**Platform →
Appliance → Network**) or over SSH:

```bash
ssh <user>@<vm> ssai-stow network                              # what it is now, and what set it
ssh <user>@<vm> ssai-stow network set --mode static \
      --address 192.168.1.50/24 --gateway 192.168.1.1 --dns 192.168.1.1,1.1.1.1
ssh <user>@<vm> ssai-stow network confirm                      # keep it (see below)
```

Set `--mode dhcp` to go back to automatic addressing; `--dns` (up to 4 servers) works in either mode
and, with DHCP, replaces the lease's resolvers. `--address` and `--gateway` are IPv4. `--ipv6` turns
IPv6 on in either mode (router advertisements, and DHCPv6 with `--mode dhcp`), with an optional static `--address6 A/P`
beside them and its `--gateway6 G`; without it the appliance has no IPv6, and an IPv6 `--dns` server is
refused. `ssai-stow network` shows the IPv6 addresses and routes too.

> **A change you can't confirm is undone for you.** Changing the address moves the appliance, which
> cuts the very session you are changing it from. So an **addressing** change is applied on a timer:
> unless you confirm it within the window (90 seconds by default, `--revert-secs`, 30 to 3600), the
> appliance restores the previous settings by itself — also across a restart or a reboot inside the
> window. Confirm from the console banner or with `ssai-stow network confirm` — if you can't
> reach the appliance at its new address, do nothing and it comes back. `ssai-stow network
> revert` undoes it at once. A **DNS-only** change cannot strand anyone, so it applies straight away
> with no confirmation (`--no-revert` does the same for any change, at your own risk).

A change that cannot be applied is refused rather than half-made: an address or a default route that
never reaches the interface within 10 seconds restores the previous settings and reports the failure
instead of leaving the appliance in between. Invalid combinations are refused before anything is
touched, naming what is wrong — a gateway outside the address's own subnet, a network or broadcast
address, a loopback or link-local address.

Settings changed here **outrank the ones given at `vm create`** and survive reboots and upgrades.
`ssai-stow network reset` (console: **Reset to install settings**) drops them and returns the
appliance to the `vm create` configuration — confirmed on the same timer, so it too comes back if you
can no longer reach the appliance afterwards.

Two things the appliance cannot do for you: the **DNS records** for its hostnames still point at the
old address, so update them to match; and with `--tls acme`, the new address must be reachable before
the next renewal.

### Duplicate an install (clone)

The same disk image serves every instance; per-install identity is what `vm create` is given. To
stand up another instance, run `vm create` again with its own host name, domains and answers. **Each
instance has its own independent, fresh database and its own secrets** — there is no DB sharing or
replication.

---

## E. Settings & environment reference

- **Per-tenant settings** — DB-backed, edited live in the admin UI with no restart (retention,
  content logging, rate limits, web search, feature toggles). Covered in the
  [Admin Guide](ADMIN_GUIDE.md).
- **Process settings** — the ~80 edge/proxy tuning knobs are surfaced in the admin
  **Settings → Advanced** tab (super-admin), centrally editable; overrides apply on the next
  restart. That tab is the supported route for all of them, on every deployment shape. A minority
  are read once at startup and so cannot be changed there. Of those, the ones with a legitimate
  reason to differ per deployment are **advanced settings** of the installer — never asked, set
  only when you give them:

  | Shape | How to set one |
  |---|---|
  | VM | `ssh -t <user>@<vm> sudo ssai-stow install --set KEY=value` (or `vm create --set` at install) |
  | Docker | `<dir>/ssai-stow --dir <dir> --set KEY=value` (or `--set` on the first install) |
  | Kubernetes | the chart value named under each setting below, in your `--values` file |

  On the VM and Docker `status` shows each one in effect; given empty, it goes back to its default. The advanced settings
  are `AUTH_MODE`, `FORWARD_AUTH_ADDRESS`, `FORWARD_AUTH_URI`, `AUTHELIA_LOGOUT_URL`,
  `HEADER_AUTH_TRUSTED_PROXY`, `HEADER_AUTH_TENANT_SLUG`, `HEADER_AUTH_TRUST_TENANT_HEADER`,
  `ALLOW_OIDC_CLAIM_EXCHANGE`, `API_DOCS_PUBLIC`, `PROXY_CORS_ORIGIN` and `RUST_LOG`. The rest are fixed by the deployment and are deliberately not
  settings you supply: listen ports, storage paths, edge-connection timeouts and CPU sizing, all of
  which derive from the machine and can only break the deployment if changed.

**Generated secrets** — made by the installer at the first install, kept by it (the VM's and Docker's
install directory, the Kubernetes release's Secret), never typed by you:

| Secret | Purpose |
|---|---|
| `ENCRYPTION_KEY` | Encrypts upstream API keys at rest. Permanent: rotating it would leave stored credentials unreadable |
| `AUTH_SECRET` | Signs sessions and tokens. Rotated with `secrets rotate` (see *Rotating `AUTH_SECRET`*), which holds the incoming or outgoing secret in a verify-only second slot while a rotation is under way |
| `INTERNAL_SERVICE_SECRET` | Authenticates the platform's own services to the admin API |
| `EDGE_TOKEN` | Authenticates the gateways to the admin API |
| `POSTGRES_PASSWORD` / `POSTGRES_APP_PASSWORD` | The database's migration and runtime roles (bundled database) |

**Install answers** (asked on every shape; `--set` or `--answers` to give them up front):

| Input | Purpose |
|---|---|
| `SETUP_ADMIN_EMAIL` | The platform (SYSTEM) super-admin. Required |
| `TENANT_NAME` / `TENANT_SLUG` | The organisation to create (default `Default` / `default`); an empty slug creates none |
| `TENANT_ADMIN_EMAIL` | Its administrator (default: the platform administrator's address); empty skips it |
| `METRICS_ALLOW` | The sources allowed to scrape metrics, as addresses or CIDR prefixes (VM and Docker; see *Monitoring*) |

Provisioning stops there: everything inside the organisation — users, providers, workspace grants,
API keys, MCP servers, policies — is set up in the console by its administrator (Admin Guide,
*Getting started*).

Provisioning generates the passwords of the accounts it creates and records them, with an operator
key and an organisation key: in `credentials.txt` on the VM and Docker, in the Secret
`<release>-stowage-provision` on Kubernetes (§ F). Each later run is handed them back. A key revoked
in the console is replaced on the next run; when a password recorded there no longer signs in (it
was changed in the console, or the database was restored from another install), or the account
exists and none is recorded for it, provisioning stops and names the account: give its current
password with `provision --set KEY=VALUE` (`k8s provision --set` on Kubernetes). An account that
signs in through an identity provider has no password to give: provisioning then asks for a key
of the organisation's `installer` service account, given as `--set TENANT_AK=…` (`OPERATOR_AK` for
the platform administrator). `--set KEY=` drops a recorded value: the next run generates it anew for
an account it creates, and stops for one that exists.

### Extensions: web search and the prompt-injection classifier

Two services that the gateway can use are not part of the product. Each is a separate extension,
released on the same registry and installed with its own installer:

| Extension | What it serves | Installer image (`docker run`) | Installer command (day-2) |
|---|---|---|---|
| Web search | A self-hosted SearXNG metasearch engine, behind the built-in web tool | `ssai-searxng-installer` | `ssai-searxng-stow` |
| Prompt-injection classifier | A text-classification service (Hugging Face Text Embeddings Inference, the ProtectAI deberta-v3-base-prompt-injection-v2 model baked in, fully offline) that the guardrail uses to screen untrusted text | `ssai-protectai-installer` | `ssai-protectai-stow` |

Fetch an extension's installer exactly as you fetch the product's (§ A, *Getting the installer*),
with its app name:

```bash
docker run --rm <registry>/ssai-searxng-installer:latest > ssai-searxng.sh
docker run --rm <registry>/ssai-protectai-installer:latest > ssai-protectai.sh
```

An extension is connected in the console, not at install:

1. **Install the extension** and note the endpoint it prints.
2. **If that endpoint is on your private network**, the platform super-admin lists it on the
   `extensions` egress list (Settings → Egress, *Internal-egress posture* below) — by host name,
   address or prefix. A public endpoint needs nothing.
3. **An organisation administrator sets it**: the web-search backend (SearXNG) under MCP Gateway →
   Web, the classifier under Settings → Guardrail. Each organisation sets its own; there is no
   platform-wide default. The built-in web tool is granted to a workspace in the console too.

The endpoint must be one the gateway can reach. An extension installed on Docker in loopback mode
prints `http://127.0.0.1:<port>`, which is the host's loopback, not the gateway container's: install
it with a domain (its front then serves it over TLS, to the addresses its allow input holds), or give
the gateway an address of the host it can reach.

On Kubernetes an extension installed in the cluster is reached at its service URL,
`http://<service>.<namespace>.svc:<port>` — a private address, so list it (step 2). With
`networkPolicy.enabled`, its port must be listed in `networkPolicy.extraEgress` unless it is 80 or
443.

**Public URLs** (per-tenant, set in Settings → Defaults; SYSTEM holds the platform default):
`proxy_public_url`, `admin_public_url`, `api_public_url` — used for quickstart snippets, OIDC
callbacks, MCP OAuth metadata, and CORS allowlists. On a fresh deploy sane defaults are
derived from the configured hostnames; operator changes in the UI win on every boot.

**Guessing automation keys is throttled by source address**
(`AUTOMATION_KEY_IP_RATE_LIMIT_MAX`, default 60 per rate-limit window; `0` turns it off). What is
counted is how many *different* keys one address has failed to authenticate with — not how often it
has failed. So a client left running with a revoked or mistyped key never trips it, however long it
runs, and one broken integration cannot throttle a site that shares its outbound address; but
somebody working through candidate keys is cut off after 60 of them, and sees `429` rather than
`401`. A key presented while the database is unreachable cannot be checked: it is answered `503`
`maintenance_in_progress`, never refused as revoked, but it counts as a key that failed — so an
address presenting more than 60 different keys during an outage stays throttled for the rest of the
window after the database is back. Browser sign-ins are untouched: they are signed-in sessions, not
automation keys.

**The gateway's public discovery documents are throttled by source address**
(`PUBLIC_METADATA_RATE_LIMIT_MAX`, default 600 per `PUBLIC_METADATA_RATE_LIMIT_WINDOW_SECS`,
default 300 seconds; `0` turns it off). Two documents have to be readable before a caller holds any
credential, because they are how a client learns which credential to present: the sign-in
information for an MCP endpoint, and an A2A agent's card. Both look up the endpoint they were asked
for, so an anonymous caller can drive that lookup as fast as it can open connections. The cap bounds
that, and the two documents share one budget per address — otherwise a caller cut off on one would
simply move to the other. Keep it generous: many users can sit behind one address. It is counted per
gateway replica, and a caller over the cap sees `429`.

**How the address of a caller is determined** (`TRUSTED_PROXY_HOPS`, default 1 — one reverse proxy
in front). This governs both throttles above and the address recorded in the audit trail. Callers
reach you through a reverse proxy, which records where it received each connection from; the setting
says how many such proxies are yours, so the gateway can tell the part of that record its own
infrastructure wrote — which a caller cannot forge — from the part the caller supplied. The appliance
and the Docker deployment put exactly one proxy in front (their TLS front end, in every mode), and so
does the Kubernetes chart (the Ingress), so the default is correct unless you add your own load
balancer or CDN in front of that. It is the same on the console/API service and the gateway — it
describes your network, not one service's policy.

Requests made through the console are attributed to the person using it, not to the console
service: the console passes on the address it was reached from, and the API counts it as one more
proxy of yours. This assumes the console and the API sit behind the **same** number of proxies. If
you put an extra proxy in front of the console only — an authenticating proxy, a WAF — console
requests are attributed to the address of the proxy in front of it instead of the person's, so the
whole console shares one sign-in limit and one address in the audit trail. Put such a proxy in front of both, or in front of neither.

**Internal-egress posture** — which private-network destinations the platform may call. By
default it reaches none: an address in a private range (RFC 1918, loopback, link-local, unique-local
IPv6 — typed as an IP literal or reached through a host name that *resolves* there) is refused on
every outbound path, so nobody inside an organisation can point a provider, an MCP server,
`web_fetch` or an A2A agent at your internal infrastructure. Public destinations always pass. The
cloud metadata endpoint (e.g. `169.254.169.254`) is refused **always**, whatever a list says.

The platform super-admin opens what a deployment needs in the console, **Settings → Egress** (the
SYSTEM tenant, at `https://<console-host>/system`), or with `PATCH /api/v1/admin/global/egress` and an operator key. There is one list
per kind of outbound call, each empty by default; an entry is

- `*` — every private address;
- an IP address or a CIDR prefix — `10.20.0.15`, `10.20.0.0/16`, `fd00::/8`;
- a host name — exactly that name (`vllm.corp.lan` does not cover `a.vllm.corp.lan`); listing a name
  trusts what your DNS answers for it.

A change applies to every new connection, on every gateway and in the console's own checks, within
seconds and with no restart, on every deployment shape — a connection already carrying a request
(a streamed answer, an open notification stream) runs to its end — and is recorded in the platform
audit trail.
No list is per organisation, and an organisation administrator cannot change one.

| List | What it covers | Who supplies the address | Risk of listing more than you need |
|---|---|---|---|
| `llm` | Model providers: requests, the server check, model discovery, replica endpoints, engine gauges | An organisation administrator | Moderate: an administrator could probe the listed range from the gateway |
| `mcp` | MCP servers and their sign-in (OAuth) endpoints | An organisation administrator | Moderate |
| `a2a` | A2A agents and their cards | An organisation administrator | Moderate |
| `oidc` | Identity providers (discovery, signing keys, token exchange) | An organisation administrator (its sign-in settings) | Moderate |
| `extensions` | The web-search backend and the guardrail classifier | An organisation administrator | Moderate |
| `upstream_token` | The sign-in endpoints an Azure OpenAI (Entra ID) or Google Vertex AI provider exchanges its stored credential at | A fixed list of Microsoft and Google endpoints | Low reach, but the request carries a live credential: list only a private stand-in |
| `web` | The `web_fetch` tool | Any end user, or a model | High: list only what users may read |
| `cimd` | An MCP client's published details | **Anyone, without signing in** | Highest: an anonymous caller makes the gateway fetch from the listed addresses |

A deployment that is entirely internal lists its own services and nothing else: a typical one lists
the vLLM servers on `llm` (`vllm.corp.lan`, or `10.20.0.0/24`), the MCP servers on `mcp`, the
identity provider on `oidc`, and the extensions on `extensions`, leaving `web` and `cimd` empty.
Mixing internal and public destinations needs nothing more: public addresses always pass, so an
internal MCP server next to a public one (GitHub's, say) needs only the internal one listed.
Prefer host names and narrow prefixes over `*`.

Private services usually present certificates from an internal CA: import it in the *Trusted CAs*
panel of Settings → System (SYSTEM super-admin). The console's own checks use it at once; a running
gateway uses it after its next restart.

**The gateway's allowed browser origins** (`PROXY_CORS_ORIGIN`, default empty: any origin) and the
**log filter** (`RUST_LOG`) are advanced settings on the VM and Docker; on Kubernetes the log filters
are `adminApi.rustLog` / `proxy.rustLog`, and the origins a `proxy.extraEnv` entry. **The public API
reference** (`API_DOCS_PUBLIC`, default on) serves the interactive API documentation at `/api/docs`
without signing in; set it `false` on a deployment that should not advertise its API (on Kubernetes,
an `adminApi.extraEnv` entry).

**The proxy that authenticates a proxy-authenticated deployment** (`HEADER_AUTH_TRUSTED_PROXY`,
default empty; **required** with `AUTH_MODE=header`). In that mode Streamscope accepts the
`X-Auth-Request-*` headers as proof of who the caller is, because a reverse proxy in front is
supposed to have already checked. That is only true if the proxy is genuinely the only way in — and
"in" includes the **API hostname**, not just the console: both answer on public addresses, and the
API is where a session is minted. Anything that can reach it while this mode is on can sign in as
any existing account, with no credential.

Streamscope cannot see whether the proxy is there, so it asks you to say so: set this to the name of
the proxy that authenticates your users (for example `authelia`). Setting it asserts that this
deployment is reachable only through it. The admin API refuses to start in proxy-authenticated mode
without it, and the Kubernetes chart refuses to render — deliberately, because the failure it
prevents is silent. Set it on Kubernetes via the Helm `adminApi.headerAuthTrustedProxy` value. If
you want single sign-on without putting a proxy in front, use OIDC with the standard mode instead;
that path verifies the provider's signature itself and needs none of this.

**Which tenant a proxy-authenticated deployment serves** (`HEADER_AUTH_TENANT_SLUG`, default empty;
`HEADER_AUTH_TRUST_TENANT_HEADER`, default `false`). These apply only with `AUTH_MODE=header`, where
a reverse proxy in front of Streamscope authenticates the user and passes their identity in
`X-Auth-Request-*` headers. That proves *who* somebody is; it says nothing about *which tenant* they
belong to — and the tenant determines what they can reach, so it must not be something a caller can
name. Set `HEADER_AUTH_TENANT_SLUG` to the tenant your deployment serves; leave it empty to serve the
system tenant.

If one deployment fronts several tenants and your reverse proxy sets `X-Tenant-Slug` itself,
per vhost, set `HEADER_AUTH_TRUST_TENANT_HEADER=true` to let that header choose. **Only do this if
the proxy overwrites the header rather than passing the caller's through** — nothing inside
Streamscope can tell the two apart, which is why it is your assertion to make. `HEADER_AUTH_TENANT_SLUG`
always wins where both are set.

**On the VM appliance and Docker, only your authentication service can set the tenant.** The built-in
TLS front end strips `X-Tenant-Slug` from every inbound request, then copies back the one your
forward-auth service answers, so with `HEADER_AUTH_TRUST_TENANT_HEADER=true` that service chooses the
tenant and a caller cannot steer it, on the console or the API hostname. Where one tenant is
served, pin `HEADER_AUTH_TENANT_SLUG` instead. The console passes on the tenant your proxy set,
never the one its own address names: a page opened under another tenant's address moves to the
tenant the deployment answered for, and anything else sent there is refused.

This matters more in proxy-authenticated mode than it first appears, because in that mode there is no
per-tenant session to constrain anyone. Signing in normally issues a session bound to one tenant and
scoped so a browser will not even send it to another. Proxy-authenticated mode has no session: the
identity headers are the credential, presented afresh on every request, so the tenant is decided per
request — and with the trust setting on and no pinned slug, it is decided by the address bar.

A user does not thereby reach *every* tenant: they land in one only if that tenant's allowed email
domains admit their address and one of its console group mappings matches the groups their
authentication service asserts, and are refused otherwise. But one authentication service asserts the
same groups everywhere, so in practice that is every tenant configured to accept those groups. Note
the refusal is not free either — being refused for want of a matching group **revokes** an existing
account in that tenant. Pinning `HEADER_AUTH_TENANT_SLUG` avoids the whole question: it wins wherever
both are set. On Kubernetes they are the Helm `adminApi.headerAuthTenantSlug` /
`adminApi.headerAuthTrustTenantHeader` values.

**Turning proxy-authenticated mode on for the VM appliance or Docker.** Set `AUTH_MODE=header`
together with `HEADER_AUTH_TRUSTED_PROXY` and `FORWARD_AUTH_ADDRESS` (the authentication service, as
`[http[s]://]host[:port]` reachable from the deployment; `FORWARD_AUTH_URI` sets the path it is asked
at, and `AUTHELIA_LOGOUT_URL` where the console's sign-out sends the browser):

```bash
sudo ssai-stow install --set AUTH_MODE=header --set HEADER_AUTH_TRUSTED_PROXY=authelia \
  --set FORWARD_AUTH_ADDRESS=authelia:9091 --set FORWARD_AUTH_URI=/api/authz/forward-auth
```

The built-in TLS front end performs the check: it removes any `X-Auth-Request-*` and `X-Tenant-Slug`
a caller sent, asks the authentication service, and forwards only the identity that service
returned. That strip happens on every request to the console and API hostnames regardless of which
sign-in mode you run, so setting `AUTH_MODE=header` without an address does not fall back to trusting
the caller — it signs nobody in. Requests to the **gateway** hostname are untouched: they
authenticate with API keys and never carry an identity header.

**The check covers the whole API hostname, including its machine-facing paths.** Automation keys,
the `ssai` CLI's own endpoints, and the MCP OAuth discovery and token endpoints all answer on
that hostname and carry no browser session, so your authentication service will reject them unless
you exempt them. Add bypass rules for `/api/v1/cli/*`, `/.well-known/*` and `/oauth/*`, or your
authentication service's equivalent, before switching the mode on. This applies equally on
Kubernetes.

On Kubernetes the equivalents are `adminApi.authMode` and `adminApi.headerAuthTrustedProxy`, but
**the stripping is yours to arrange** — the chart adds no authentication to the ingress and does not
remove inbound headers. Put your authenticator in front of both the console and API hosts, and
configure it to discard any inbound `X-Auth-Request-*` and `X-Tenant-Slug` before setting its own.
Without that, anything that can reach either host can sign in as any account.

**Asserted-identity provisioning** (`ALLOW_OIDC_CLAIM_EXCHANGE`, default `false`). Streamscope
signs users in by verifying the identity provider's signature itself, and needs nothing enabled to
do so. This setting additionally lets another internal service assert an identity on its own word —
both for **console** admins and for **portal** users — useful only where you already provision
accounts from your own verified identity source. Leave it off; while off neither path is available.
Set it on the VM and Docker with `--set ALLOW_OIDC_CLAIM_EXCHANGE=true`, and on Kubernetes as an
`adminApi.extraEnv` entry.

**Media size limit** (`EDGE_BLOB_MAX_MB`, default 32). The largest media file — a generated image,
an audio clip, an uploaded document — that is kept in the audit trail when an organization enables
media storage; each organization's own media size setting is held to it, and a larger file is
recorded as a stripped placeholder. The admin API and every gateway read it at startup and must
agree. It is fixed at its default on the VM appliance and the Docker deployment; on Kubernetes it can
be changed by setting the same value as an entry in both `adminApi.extraEnv` and `proxy.extraEnv`. A
higher value costs memory on both while a large file is in transit: keep it well under each
service's memory limit.

**Response-cache capacity** (`RESPONSE_CACHE_MAX_MB`, unset by default: 15% of the gateway
replica's memory limit, or 256 MB when it has none; `0` refuses every store;
`RESPONSE_CACHE_MAX_ENTRIES_PER_TENANT`, default 2000). The response cache is in-memory on each
gateway replica, so these bound how much RAM it may hold: the first is the total across all tenants
on one replica, the second stops any single tenant filling it. Left unset, the first grows with the
replica's memory limit. Cached answers never survive a
restart — a fresh replica simply recomputes. Whether caching is used at all is a tenant decision
(Admin Guide → Response cache); these only cap what the process will hold when it is. Raise them on
a memory-rich host serving heavily repeated traffic; when the ceiling is reached, responses are
still served normally and simply not stored, which the audit trail records.

### Monitoring — Prometheus metrics

Both services expose a Prometheus scrape endpoint at `/metrics` on a **dedicated internal port**,
never on their public service ports:

- **Gateway** — request/error totals, responses by HTTP status class, active streams, a
  gateway-overhead histogram (the platform's own processing time, excluding the upstream provider),
  an end-to-end request-latency histogram (measured from the moment the upstream call starts, so
  model generation time dominates), pending locally-buffered audit records, when the console last
  had nothing newer for the gateway, and container CPU/memory.
- **Admin API** — database-pool utilisation, responses by status class, uptime.

The endpoint is **unauthenticated by design** and carries no tenant or conversation data — only
aggregate operational counters. Each deployment shape confines it:

- **VM appliance and Docker**: the built-in front end serves each endpoint as a route of its own —
  `metrics-gateway` and `metrics-api`, on their own hostnames in a TLS mode
  (`https://<metrics-gateway-host>/metrics`) — and answers only the source addresses listed in
  `METRICS_ALLOW` (IP addresses and CIDRs, separated by commas or spaces). Every other source gets
  `403`, and **while it is empty, everyone does**. Set it at install or later:
  `--set METRICS_ALLOW=10.0.0.5,192.168.10.0/24`. The source is the address the front end sees: a
  Prometheus on another host keeps its own, while a request from the Docker host itself may arrive
  from the Docker bridge's gateway address.
- **Kubernetes**: enabled by default on port 9464 (`metrics.port`; set `0` to disable). The port
  stays cluster-internal (ClusterIP); with the chart's NetworkPolicy enabled it is unreachable
  until you allowlist your monitoring namespace via `metrics.scrapeNamespaceSelector`
  (e.g. `{kubernetes.io/metadata.name: monitoring}`). If you run the Prometheus Operator, set
  `metrics.serviceMonitor.enabled: true` to get scrape configuration for both services
  automatically.

All counters and histograms are cumulative since process start (standard Prometheus semantics) —
use `rate()` / `increase()` / `histogram_quantile()` over them. Useful starting points:
`streamscope_proxy_requests_total`, `streamscope_proxy_responses_total{class="5xx"}`,
`streamscope_proxy_overhead_seconds` (is the platform adding latency?),
`streamscope_proxy_request_duration_seconds` (how slow are providers?), and
`streamscope_proxy_content_bytes_shipped_total` with `…_bodies_shipped_total` (the conversation
content a gateway sends the console, every resend included — a gateway names what the console
already stored from it rather than sending it again, so in a steady state these grow with what
sessions add rather than with their length).

**A gateway that cannot reach the console keeps serving** the configuration it last received. A
gateway restarted during the outage starts from the copy it saved on disk and logs that it does —
on the VM appliance and Docker, and on Kubernetes when a gateway container restarts inside its pod
(a new pod is not ready until the console answers). Each failed attempt to reach the console logs a
warning. Changes made in the console meanwhile — a revoked key, a removed provider — reach the
gateway only when the console answers again.

`streamscope_proxy_config_synced_timestamp_seconds` is the Unix time the console last had nothing
newer to send the gateway; it is `0` from a start until the first time it does. Alert
on `time() - streamscope_proxy_config_synced_timestamp_seconds > 300` (stale, or never current since
the start) with a `for:` longer than your gateways take to become ready, so a normal start does not
fire it. A configuration change the gateway cannot read is refused and logged as an error, and
does not hold the metric back.

---

## F. Kubernetes deployment

The Kubernetes form factor runs the **same container images** as the VM appliance through a **Helm
chart**, installed and operated by `ssai-stow k8s`. It is the right choice when you already
operate Kubernetes and want horizontal scale: the gateway and control plane scale out in pods, the
database is a **managed Postgres outside the cluster** (or a CloudNativePG cluster), and TLS is
terminated by your Ingress controller with cert-manager. Backups, high availability, and storage are
owned by the database platform — not the chart.

Everything you configure later in the Admin Guide (tenants, providers, workspaces, policy) is
identical to the VM appliance; only the install and lifecycle differ.

### What you need

- A **Kubernetes cluster** (1.27+) and `kubectl` + `helm` (3.14+) configured against it — the
  installer drives your own `helm` and `kubectl`, on the current context (`--kube-context` for
  another).
- **Docker** on the machine you install from, to fetch the installer (§ A).
- A **managed Postgres** reachable from the cluster (Amazon RDS, Google Cloud SQL, AlloyDB, or any
  PostgreSQL 18+). In-cluster Postgres is supported too — **CloudNativePG** for high availability, or a
  single-pod database for evaluation only.
- An **Ingress controller** (e.g. ingress-nginx) and **cert-manager** with a configured issuer
  (e.g. a Let's Encrypt `ClusterIssuer`).
- **DNS** records for your two public hostnames — the admin console and the gateway.

The installer pulls the chart and names every image by digest. The release's packages are public,
so the cluster needs no pull Secret, unless you install from a mirror that asks for a sign-in.

### Step 1 — Prepare the database

There are **three database modes**; pick one with `postgres.mode`, then do that mode's one-time
prep below:

| Mode | Use it for | Backups / HA | Prep before install |
|---|---|---|---|
| `external` *(default, recommended)* | a **managed Postgres outside the cluster** (RDS, Cloud SQL, AlloyDB, or any PostgreSQL 18+) | owned by the managed provider | create the database and the roles (below) |
| `cnpg` | **in-cluster high availability** via the CloudNativePG operator (a multi-instance Postgres cluster) | owned by CloudNativePG | install the CloudNativePG operator (below) |
| `embedded` | **evaluation only** — a single Postgres pod, no high availability | none — do not run production data on it | nothing — the chart provisions it |

Streamscope uses **two login roles** and three non-login roles, the same contract on every
deployment:

| Role | When | Privilege |
|---|---|---|
| migration role | startup only — runs schema migrations | owns the schema, installs the `pg_trgm` and `btree_gin` extensions (a **non-superuser** is sufficient on managed Postgres) |
| `streamscope_app` | runtime | least-privilege, row-level-security enforced — **no superuser, ever** |
| `streamscope_global`, `streamscope_ingest` | runtime, one transaction at a time | granted to `streamscope_app` so it can switch to them, **never inherited** |
| `streamscope_lookup` | never logs in | granted to the **migration role only** — never to `streamscope_app` |

**Connect directly, or through a session-mode pooler only.** Streamscope keeps per-connection state
— which tenant a connection serves, which role it runs as — for as long as it holds the connection. A
pooler in **transaction** mode (PgBouncer `pool_mode = transaction`, RDS Proxy connection
multiplexing, a managed database's built-in transaction pooler) hands one database connection to
several clients between their transactions, so that state would apply to another client's queries:
one tenant could read another's data. Point `DATABASE_URL` at the database itself or at a pooler in
**session** mode (PgBouncer `pool_mode = session`); RDS Proxy is fine only while it pins every
connection, which you cannot rely on, so prefer the database endpoint.

Streamscope refuses to start if `streamscope_app` holds the privileges of any of the three non-login
roles implicitly (a plain `GRANT`, which inherits by default, or a grant through another role), or if
one is missing — the grants must be exactly as below.

**`external` — managed Postgres.** A DBA does a one-time setup on the Postgres instance. The **migration
role** (`<migration_role>` below) is the login role your automation connects as to run migrations —
it can be the managed instance's existing owner/master user (e.g. the RDS master user, a Cloud SQL
user) or a dedicated login you create; it needs the grants below but **no superuser**. Run once:

```sql
-- 1. Create an empty database with Streamscope's locale (the database both connection URLs you
--    give the installer name). A database's locale is fixed when it is created: one made
--    without these clauses (your provider's default) is refused.
CREATE DATABASE streamscope
  ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'PG_UNICODE_FAST'
  LC_COLLATE 'C' LC_CTYPE 'C.UTF-8' TEMPLATE template0;

-- 2. Connected to that database, set up the roles:
CREATE ROLE streamscope_app LOGIN PASSWORD '<strong-password>' NOBYPASSRLS;  -- runtime role
CREATE ROLE streamscope_global NOLOGIN;
CREATE ROLE streamscope_ingest NOLOGIN;
CREATE ROLE streamscope_lookup NOLOGIN;
GRANT streamscope_global TO streamscope_app WITH INHERIT FALSE, SET TRUE;  -- switch-to only
GRANT streamscope_ingest TO streamscope_app WITH INHERIT FALSE, SET TRUE;  -- switch-to only
GRANT streamscope_app    TO <migration_role>;  -- lets migrations hand table ownership to the app role
GRANT streamscope_lookup TO <migration_role>;  -- lets migrations hand the lookup functions to it
ALTER SCHEMA public OWNER TO <migration_role>;     -- (or grant CREATE on the schema)
GRANT CREATE ON DATABASE streamscope TO <migration_role>; -- to install the trusted pg_trgm and btree_gin extensions
```

Streamscope requires **PostgreSQL 18 or later** and stops at start on an older server, or on a
database whose locale is not the one above — every deploy shape creates its database with it, so
search and case-insensitive matching treat accented and non-Latin letters the same everywhere. The
first migration checks every role and grant above and stops with an error naming what is missing.

With the runtime role pre-created this way, the chart leaves it untouched (it never resets a
password it does not own). Nothing needs `SUPERUSER` at migrate or run time. The installer asks for
the two connection strings at install (Step 3):

- `MIGRATION_DATABASE_URL` = `postgres://<migration_role>:<pw>@<db-host>:5432/streamscope`
- `DATABASE_URL` = `postgres://streamscope_app:<pw>@<db-host>:5432/streamscope`

> **Connections.** Each control-plane replica opens up to 32 database connections (30 pooled, one
> held for notifications, one while it migrates at start), and the gateways open none. Size the
> instance's `max_connections` for 32 per control-plane replica — counting both the old and the new
> replica during a rolling update — plus your own tooling.

> **TLS.** Most managed providers require an encrypted connection. Append the appropriate `sslmode`
> to **both** URLs — e.g. `?sslmode=require` (encrypt only) or `?sslmode=verify-full` (encrypt +
> verify the server certificate, recommended). If `verify-full` needs the provider's CA, point
> `sslrootcert` at it.

**`cnpg` — in-cluster HA.** Install the [CloudNativePG](https://cloudnative-pg.io) operator, 1.27.1
or later (the first to run PostgreSQL 18), into the cluster first (one-time, e.g. `kubectl apply -f` its release manifest). That is the
only prep: CloudNativePG provisions the database — on the release's PostgreSQL, with the locale above
— the migration role and the `streamscope_app` runtime role (with the passwords the installer
generates for the release), and the three non-login roles with the grants above — so you **do not**
pre-create roles or give any connection strings, and the cluster runs with **no superuser account at
all**. To back the database up (*Backups, HA, and scaling*), also install CloudNativePG's [Barman
Cloud Plugin](https://cloudnative-pg.io/plugin-barman-cloud/) beside the operator (it needs
cert-manager).

**`embedded` — evaluation.** No prep. The chart runs a single Postgres pod with passwords the
installer generates. Single-pod, no HA — never put production data on it.

### Step 2 — Write your values

Your values file holds what is yours to decide — hostnames, TLS issuer, database mode, scaling. Start from this:

```yaml
hostnames:
  adminUi: admin.example.com          # the console
  proxy: gateway.example.com          # the gateway
ingress:
  className: nginx
  tls:
    certManager:
      issuerName: letsencrypt-prod    # your cert-manager (Cluster)Issuer
      issuerKind: ClusterIssuer
postgres:
  mode: external                      # external | cnpg | embedded
proxy:
  autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 10 }
```

The secrets are not in it: the installer generates them, and asks for the inputs, into a Secret of
the release's own (Step 3).

Web search and the prompt-injection classifier are extensions, connected in the console (§ E,
*Extensions*).

The Ingress sends `Strict-Transport-Security` whenever it terminates TLS, since that is the layer
that knows whether the certificate is publicly trusted. If you front the cluster with a **private
CA**, turn it off — `ingress.hsts.enabled: false`. An HSTS pin makes a certificate warning
impossible to click through, so a browser that does not already trust your CA would be locked out of
the console, and the pin outlives the deployment that set it. The annotation is written for
**ingress-nginx**; on another controller set your own equivalent through `ingress.annotations` and
disable this one.

The Ingress also raises ingress-nginx's proxy read and send timeouts to 15 minutes
(`ingress.proxyTimeoutSeconds`, default `900`). A request the gateway holds for upstream capacity
sends nothing until it is served — up to `QOS_QUEUE_TTL_MAX_MS`, 9 minutes by default — and the
controller's own 60-second default would end it with a 504 first. Keep the value above that maximum
plus your longest answer; an annotation of the same name under `ingress.annotations` wins, and on
another controller set its equivalent there. The chart has one Ingress for all three hostnames, so the
console and API hosts get the same timeouts — harmless, since they answer quickly.

### Step 3 — Install with `ssai-stow`

```bash
sh streamscopeai.sh k8s install --values values.yaml [--namespace streamscopeai] [--release streamscopeai]
```

It asks the install answers (§ E) on a terminal — the platform administrator, the organisation, its
administrator, and, with `external`, the two database URLs — never echoing a secret one. Without a terminal, give them with `--answers FILE`
(a YAML map, `KEY: value`; keep it `0600`) or `--set KEY=VALUE`, and `--no-input`.

Then it:

- creates the namespace if needed, and applies the release's Secret, **`<release>-stowage`**:
  the generated secrets (§ E) and your answers. An existing one is reused — its values are never
  generated or asked again;
- runs `helm upgrade --install` of the release's chart, with its images pinned by digest, then your
  `--values`, waiting (`--timeout`, default 10m) until every component is ready — a release that
  does not become ready is rolled back;
- once the release is ready, runs **provisioning** as the Job `<release>-stowage`: it creates the
  platform administrator, the organisation and its administrator, generating each account's
  password, an operator key and an organisation key. These are
  recorded in the Secret **`<release>-stowage-provision`** — never in a pod log — and handed back to
  every later run, so it is idempotent. The installer prints the names of what it recorded, never
  the values; read one with
  `kubectl -n <ns> get secret <release>-stowage-provision -o jsonpath='{.data.SETUP_ADMIN_PASSWORD}' | base64 -d`.
  The Job runs again after every `k8s upgrade` and `k8s reset-db`, and is deleted once it ends, its
  log copied to the installer's output. If it fails, the release keeps running and the error names
  the fix; `ssai-stow k8s provision` runs it again (`--set KEY=VALUE` corrects a value it
  recorded or gives one it did not record; `--set KEY=` drops one, generated anew only for an
  account the run creates). `--no-provision` installs without it.

The account you install with needs, besides what helm needs for the chart, the grants that Job uses:
create, get, list, watch and delete `jobs`; get, list and watch `pods` and get `pods/log`; create
and patch `serviceaccounts`, `roles` and `rolebindings`; get, create and patch `secrets`; get
`configmaps`. The installer checks them before it changes anything.

**Network settings for the pods** (optional). `k8s install --unsafe-sysctls` (and `k8s upgrade`)
gives the gateway, the API, the console and the embedded database the network settings of a busy
server (listen queues, latency and MTU probing); a CloudNativePG database's pods are the operator's
and get none. Each node's kubelet must allow them (`--allowed-unsafe-sysctls`), and the namespace's
Pod Security level must accept them (`privileged`): the installer refuses a namespace that does not.
`ssai-stow k8s tune` prints the settings, the kubelet setting they need, and how a node itself is
tuned. Without the flag the pods run with the cluster's defaults.

`--dry-run` checks everything, then prints the Secret values it would add (secrets redacted), the
values file and the helm command, and changes nothing. `--image-registry` and `--registry-ca` install
from a mirror (§ A).

Readiness probes hold each component out of rotation until it can actually serve, so the rollout
only reports success once the system is live. Point your DNS at the Ingress address, then browse to
`https://<console-host>/system` and sign in with the platform administrator. For ongoing **scripted
provisioning** (tenants, providers, OIDC), mint an **operator key** rather than scripting a human
login — see [§ D, Automating the admin API](#automating-the-admin-api-operator-key).

**Keep a copy of the release's Secret off the cluster** — it holds `ENCRYPTION_KEY`, without which a
restored database cannot decrypt its stored provider credentials:
`kubectl -n <ns> get secret <release>-stowage -o yaml`, stored in your secret store.

### Step 4 — Verify the install

admin-api binds only **after** migrations apply — a fresh install shows the pod `Pending`/`NotReady`
until its startup probe (`/ready`) first succeeds, and the proxy stays not-ready until it has pulled
config from a ready admin-api. The Deployments are named `<release>-streamscopeai-<component>` —
with the default release (`streamscopeai`), `streamscopeai-streamscopeai-admin-api`:

| # | Check | Pass criteria |
|---|---|---|
| 1 | `ssai-stow k8s status` | the release, version and channel; helm reports `deployed` |
| 2 | `kubectl -n <ns> get pods -l app.kubernetes.io/instance=<release>` | all pods `Running`/`Ready`, no `CrashLoopBackOff` |
| 3 | `curl -I https://<console-host>/` | a redirect to the portal, valid cert from your issuer |
| 4 | Browser → `https://<console-host>/admin` → sign in | lands on the dashboard |

If a pod stays `Running` but never `Ready`, read its logs (next section) — a degraded boot (failed
migration) holds `/ready` at `503 MIGRATION_FAILED` so it never serves traffic.

### Day-2 — Upgrade & rollback

Upgrades and rollbacks go through the installer. As on the VM, read the changelog of every release
between yours and the target first: a **BREAKING** entry names what to do around the upgrade.

```bash
# Upgrade to a named release (fetches that release's installer and runs its upgrade).
sh streamscopeai.sh k8s upgrade --version <release> [--values values.yaml]
# Or, with the new release's own installer:
sh streamscopeai.sh k8s upgrade [--values values.yaml]
# Replace recorded install answers (a secret one included) from a file, restarting what reads them:
# `project: streamscopeai` and `inputs` of `KEY: value` (a `tls` section is left out: the ingress owns TLS).
sh streamscopeai.sh k8s upgrade --given answers-given.yaml

# Roll back to the previous release (or name a helm revision with --revision N).
sh streamscopeai.sh k8s rollback
```

An upgrade reuses every value given before (`--values` adds to them — it is also how you change a
value on the same release), adds to the Secret what the new release introduces (asked as at install),
and waits for readiness (`--timeout`, default 6m): a release whose pods don't go Ready in time is
rolled back by helm. `rollback` goes back to the latest revision that deployed before the one
running; `helm -n <ns> history <release>` lists the revisions.

The previous release reads past database changes it does not know, so a rollback also works after an
upgrade that changed the database. A database change older releases cannot run on (its release says
so in the changelog) is the exception: the older admin-api then answers `503 MIGRATION_FAILED`
naming the reason and its pods never become ready, so the rolling update keeps the current admin-api
pods serving — recover from the restore point taken before the upgrade instead.

Take a restore point before every upgrade — a snapshot of the managed database, or with `cnpg` an
on-demand backup with CloudNativePG's kubectl plugin (`kubectl cnpg backup -n <ns>
<release>-streamscopeai-postgres --method=plugin --plugin-name=barman-cloud.cloudnative-pg.io`), then
wait for its `Backup` to complete (`kubectl -n <ns> get backups`). The chart
keeps no backup of its own to fall back on.

**Rotating `AUTH_SECRET`**: `ssai-stow k8s secrets rotate AUTH_SECRET --stage`, then without a
flag, then `--finish` (see *Rotating `AUTH_SECRET`* in § B); each pass restarts the pods that read it,
one at a time, and nobody is signed out.

### Day-2 — Diagnostics & recovery

Everything is driven with `ssai-stow k8s` plus ordinary `kubectl` + `helm` — there is no
separate host daemon. The control plane splits liveness (`/health`, always 200) from readiness
(`/ready`, 200 only when the database is reachable, the gateways' configuration has been prepared,
and the boot isn't degraded), so a pod that is `Running` but not `Ready` is serving no traffic and
is safe to inspect.

```bash
ssai-stow k8s status                                                       # what the release runs, helm status
kubectl -n <ns> get pods -l app.kubernetes.io/instance=<release>         # who is unhealthy
kubectl -n <ns> logs deploy/<release>-streamscopeai-admin-api --tail=100   # control-plane / migration logs
kubectl -n <ns> logs deploy/<release>-streamscopeai-proxy --tail=100       # gateway logs
ssai-stow k8s provision                                                    # provisioning again, its log on the terminal
helm -n <ns> history <release>                                           # revisions for rollback
```

Common scenarios, least to most severe:

1. **An upgrade broke the rollout** — helm rolls back a release whose pods don't go Ready in time.
   To go back further, `ssai-stow k8s rollback [--revision N]`.
2. **Migration failed at boot** — admin-api does **not** exit; it stays `Running` and answers
   `503 MIGRATION_FAILED` on `/ready`, leaving the database at the prior version as if the migration
   never ran. Read the reason in the admin-api logs. Recover with `k8s rollback` to the prior release
   (the database is still at the prior version) **or** fix forward with a corrected release. The
   proxy stays not-ready until admin-api is ready again, so no traffic is served degraded.
3. **Pods can't pull images** (`ImagePullBackOff`) — from `ghcr.io`, check that the nodes reach it
   (egress, proxy); from a mirror, check your `imagePullSecrets` and that the nodes trust the
   mirror's CA.
4. **Console unreachable / no cert** — check the Ingress has an address and cert-manager issued the
   certificate (`kubectl -n <ns> get ingress,certificate`); a stuck cert is usually a DNS record not
   yet pointing at the Ingress, or a misconfigured issuer.
5. **Starting over on an evaluation install** — `ssai-stow k8s reset-db [--yes]` uninstalls the
   release, deletes the `embedded` database's volume and installs it again with the same Secret and
   values; provisioning then seeds the empty database, with new passwords. With `cnpg` backups on,
   give `postgres.cnpg.backup` a new `serverName` for the new cluster (or empty its folder in the
   object store first): CloudNativePG refuses to archive into a folder that already holds another
   cluster's WAL, and the new cluster would stay in setup. A database outside the release
   (`external`) is not touched.
6. **Database lost** — always with the release's Secret as it was: its `ENCRYPTION_KEY` must be
   the one the data was written with. **The chart keeps no database backup of its own** (see
   *Backups, HA, and scaling* below).
   - `external` — restore through your provider (a snapshot or a point-in-time restore) behind the
     endpoint the two URLs name, then restart the control plane
     (`kubectl -n <ns> rollout restart deployment/<release>-streamscopeai-admin-api`).
   - `cnpg`, from its backups — the cluster is created again from the object store. Delete what is
     left of the lost one (`kubectl -n <ns> delete cluster <release>-streamscopeai-postgres`, which
     also deletes its volumes), then upgrade the release with a values file that names the store to
     restore from and a **new** folder to archive into — CloudNativePG refuses to archive into a
     folder that already holds the lost cluster's WAL (the chart refuses a restore that would
     archive into the very folder it reads; the same name in another store, or on another endpoint,
     is fine):

     ```yaml
     postgres:
       cnpg:
         recovery:
           objectStore: { … }        # the store the backups are in (the backup.objectStore you used)
           serverName: <folder>      # the lost cluster's backup.serverName (empty there: <release>-streamscopeai-postgres)
           # recoveryTarget: { targetTime: "2026-10-27 08:00:00+00" }   # a point in time; default: the latest WAL
         backup:
           serverName: <new-folder>
     ```

     `sh streamscopeai.sh k8s upgrade --values restore.yaml --timeout 60m` — the same release the
     backup was taken from, and a timeout long enough for the restore. The cluster is rebuilt from
     the latest base backup and replays the archived WAL, the roles take the release's passwords
     again, and the control plane reconnects on its own. Take an on-demand backup then (the new
     folder holds none until the next scheduled one), and keep `backup.serverName` from then on; the
     `recovery` values are read only when the cluster is created, so they may stay.

### Hardening

The deployment ships hardened by default and matches the appliance's container posture: every
workload runs as a non-root user with no privilege escalation, all Linux capabilities dropped, the
default seccomp profile applied, and a **read-only root filesystem** (each writes only to a small
scratch area), and none is given a Kubernetes API token. Every workload also carries **CPU and memory
requests and limits** so it schedules predictably and cannot starve its neighbours; adjust them under
each component's `resources` key. Each container is given only the secrets it reads, one key at a
time.

One control is **opt-in** because it depends on your cluster's networking: set
`networkPolicy.enabled: true` to apply a **default-deny network posture**. Public traffic then reaches
the gateway and console only through your Ingress controller (`networkPolicy.ingressNamespace`); the
control API accepts only the internal components that call it; the in-cluster evaluation database
accepts only the control API; and outbound traffic is limited to DNS, the database, and web
endpoints. If an upstream you use listens on a non-standard port, add it under
`networkPolicy.extraEgress`. With the policy enabled the Prometheus metrics port is also closed by
default — allowlist your monitoring namespace via `metrics.scrapeNamespaceSelector` (see § E
Monitoring). This requires a CNI that enforces NetworkPolicy (Calico, Cilium, or an equivalent
built-in controller); on a cluster whose CNI ignores NetworkPolicy the rules are inert, so confirm
enforcement before relying on them.

### Backups, HA, and scaling

- **Backups belong to the database platform.** The chart runs no backup job of its own: on
  Kubernetes the database owns backup, failover and elastic storage. With `external`, configure them
  at your provider. With `cnpg`, give the chart CloudNativePG's backup configuration (it needs the
  Barman Cloud Plugin, Step 1) — a continuous WAL archive plus a base backup every night, in an object
  store of yours:

  ```yaml
  postgres:
    mode: cnpg
    cnpg:
      backup:
        objectStore:                    # the plugin's ObjectStore spec, passed through as is
          configuration:
            destinationPath: s3://my-bucket/streamscope/
            s3Credentials:              # a Secret you create in the release's namespace
              accessKeyId:     { name: streamscope-backup, key: ACCESS_KEY_ID }
              secretAccessKey: { name: streamscope-backup, key: ACCESS_SECRET_KEY }
            wal: { compression: gzip }
          retentionPolicy: "30d"
        schedule: "0 0 3 * * *"         # base backups; six fields, seconds first
  ```

  `objectStore` takes every provider the plugin supports (S3 and compatibles, Azure Blob, Google
  Cloud Storage) and workload identity in place of a key Secret; see the plugin's documentation. The
  first base backup is taken as soon as backups are on; `kubectl -n <ns> get backups` lists them.
  Keep the copy of the release's Secret beside the backups: a restored database is unreadable
  without its `ENCRYPTION_KEY`. Restoring: *Diagnostics & recovery*, scenario 6.
- **Standby and failover, per database mode.**
  - `external` — turn on the provider's high-availability option (RDS Multi-AZ, Cloud SQL high
    availability, AlloyDB's primary instance) and give both connection URLs the endpoint that always
    names the **current primary** — never a read replica or a reader endpoint: Streamscope writes
    through every connection it opens. Prefer an option that replicates **synchronously**.
  - `cnpg` — the cluster runs `postgres.cnpg.instances` instances (3 by default): one primary and
    streaming standbys, which CloudNativePG promotes on a failure or on a switchover you ask for.
    Streamscope connects to the cluster's read-write service, which always routes to the primary, so a
    failover needs nothing from you. The cluster replicates **asynchronously** (CloudNativePG's
    default).
  - `embedded` — no standby, no failover, no backup: evaluation only.

  With asynchronous replication, a failover loses the transactions the standby had not yet received
  — including audit records the gateways had already delivered and dropped from their buffers.
- **During a failover** (or any database outage) the control plane reports not ready, so Kubernetes
  stops routing to it; it does not restart, and it is ready again on its own once the new primary
  answers. Meanwhile the console, sign-in and the admin API are unavailable. The gateways keep
  serving the traffic of every key they already know, with the configuration they hold; budgets and
  rate limits are still enforced, against the last fleet-wide totals plus each gateway's own usage
  since. Each gateway holds its audit records until the control plane is back — up to 1 GiB per
  gateway by default (`EDGE_OUTBOX_MAX_MB`, Settings → Advanced; past it the oldest records are
  dropped and logged) — and the *pending locally-buffered audit records* metric shows how much is
  waiting. That buffer is the gateway pod's temporary storage: a gateway pod replaced, drained or
  scaled in while the control plane is unreachable loses the audit it still holds (with the control
  plane up, a stopping pod first delivers what it can within its shutdown drain). Avoid restarting,
  draining or scaling in gateway pods until the database is back; before planned database work,
  raise `proxy.autoscaling.minReplicas` to the current count, since a gateway waiting on the
  database uses little CPU and the autoscaler may scale it in.
  A control-plane pod that *starts* while the database is unreachable exits after about 90 seconds
  and is restarted by Kubernetes until it connects.
- **Scaling.** The gateway (proxy) autoscales by default (a Horizontal Pod Autoscaler on CPU);
  the control plane (admin-api) can opt into the same. Replicas coordinate through the database and
  share request limits across the fleet, so adding pods adds throughput with no shared state to
  manage. When the control plane autoscales, set its replica upper bound so per-pod rate limits add up
  to the intended total (the chart wires this from the autoscaling `maxReplicas`).
- **Per-pod CPU sizing.** Each gateway and control-plane pod sizes its internal worker pool to the
  CPU it is granted, not to the node's core count. The chart sets no CPU *limit* by default (a CPU
  limit would let the scheduler throttle the latency-sensitive gateway), so it pins a worker-thread
  count instead: `proxy.workerThreads` and `adminApi.workerThreads` (default `2`) — raise these to
  give each pod more CPU before the HPA adds replicas, or set `0` and add a `resources.limits.cpu` to
  have each pod auto-size to that limit. The pod's reported CPU and memory reflect real container
  usage (the same figures `kubectl top` shows).
- **Availability during disruptions.** Any tier that runs more than one replica automatically gets a
  **PodDisruptionBudget** (keeping at least one replica up through node drains and cluster upgrades)
  and **soft anti-affinity** that spreads its replicas across nodes, so a single node loss cannot take
  a whole tier down.

---

## G. Docker deployment

The shortest path to a running system: one command on any machine that runs Docker. It brings up the
gateway, the console and a database, generates every secret, and creates the platform
administrator and an organisation with its administrator — from there, the organisation is set up
in the console.

Use it to evaluate Streamscope, and to run it where a single host is the right size. For elastic
capacity or a managed database, use Kubernetes (section F); for an appliance with atomic A/B
upgrades and off-host backups, use the VM (sections B–D). All three run the same containers, so
anything you configure afterwards is identical.

### What you need

- A machine with **Docker** and its **Compose plugin** (`docker compose version` reports 2.20 or
  newer). The separate `docker-compose` command is a retired version and is not supported.
- About **4 GB of memory** free for the base stack, and 8 GB if you turn on the optional
  prompt-injection guardrail. The services grow with the host: at every start the database, the
  gateway and the admin API are each given a share of the host's memory (30 %, 20 % and 10 %, up
  to 16 GB, 8 GB and 4 GB), never less than the base stack's own limits. The shares are ceilings:
  the gateway and the admin API reach them only under load, while the database keeps a quarter of
  its share as its cache, filled as data is read. On Docker Desktop, whose containers run in a VM of their own, the services
  keep the base limits.
- Access to the release registry (§ A). Nothing else — no source tree, no language runtimes, no
  database to prepare.

### Step 1 — Install

```bash
docker run --rm <registry>/streamscopeai-installer:latest > streamscopeai.sh && sh streamscopeai.sh
```

It asks where to install (default `./streamscopeai`), checks Docker, Compose and the ports, asks how to
serve (loopback by default), then a handful of questions — the install answers of § E, all of which
have sensible answers already filled in — and shows them for review. Then it:

- writes the deployment into the install directory,
- generates the encryption key, the signing secret and the database passwords,
- pulls the release's images by digest, starts the stack and waits for it to be ready,
- creates a platform administrator and an organisation with its own administrator,
- and saves their credentials to `streamscopeai/credentials.txt` (readable only by you).

Pressing Enter at every question gives an organisation named `Default`, whose administrator uses the
platform administrator's email address. They are separate accounts, each with its own generated
password.

When it finishes it prints the console host's address: by default `http://127.0.0.1:3000` (the
users' portal at `/`, the organisation's console at `/admin`, the platform's at `/system`) and the
gateway on `http://127.0.0.1:8080/v1`. `ssai-stow status` prints every route's URL.

To install without being asked anything, add `--no-input` and give the answers with `--set KEY=VALUE`
or `--answers answers.yaml` (a YAML map, `KEY: value`, with an optional `tls` section — `mode`, `cert`,
`key`, `ca`, paths relative to the file — so one file describes the whole install), or `--given FILE|-`
(the same answers and TLS material as PEM, from a file or standard input: § D); add `--no-provision`
to create even the platform administrator yourself, in the console's setup page.

Useful options:

| Option | What it does |
|---|---|
| `--dir D` | the install directory (default `./streamscopeai`) |
| `--tls MODE --domains …` | serve over HTTPS on real hostnames — see *Going beyond your own machine* |
| `--ports console=3100,gateway=8180,…` | loopback ports per route (`console`, `api`, `gateway`, `metrics-api`, `metrics-gateway`) |
| `--address 127.0.0.2` | another loopback address, e.g. to run two installs side by side (`::1` for IPv6) |
| `--ipv6` | IPv6 on the install's network (Docker 27 or later), so the front sees an IPv6 client's own address |
| `--registry PREFIX --registry-ca FILE` | pull from a mirror (§ A) |
| `--offline` | use images already loaded on the host; no registry contact |
| `--dry-run` | print every value it would record (secrets redacted), and change nothing |

Nothing is pulled or written until every check has passed — free ports, Docker and Compose versions,
and with `--offline` every image present — and a failed first install removes the directory it
created, so running it again with the fixing option starts clean. For example, when something
already holds port 3000:

```bash
sh streamscopeai.sh --ports console=3100
```

**Without registry access**, prefer a mirror (§ A). Otherwise, load the release's images on the host
(`docker load`, keeping the release's tags — including the TLS front end's,
`<registry>/streamscopeai-front:<tag>`) and install with `--offline`: each image is checked against
the release, and any that is missing is named. Make the archive on a host with the same kind of
Docker image store as the target.

### Step 2 — Set up the organisation in the console

Sign in at `http://127.0.0.1:3000/admin` as the organisation administrator from `credentials.txt`, then,
as the Admin Guide's *Getting started* describes:

1. add your model provider under **Providers** — its API key, or the address of a self-hosted
   server;
2. allow the **Default** workspace to use it;
3. add yourself (or your users) to the workspace and create an **API key**.

A provider on your own network — a vLLM or Ollama server on the LAN, say — is a private address,
which the platform refuses until it is listed: sign in as the platform administrator at
`http://127.0.0.1:3000/system` and add it to the `llm` list under **Settings → Egress** first (§ E,
*Internal-egress posture*).

### Step 3 — Check it works

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer <the API key you created>" \
  -H "Content-Type: application/json" \
  -d '{"model":"<a model listed in the console>","messages":[{"role":"user","content":"hello"}]}'
```

The request appears in the console under **Audit** within a second or two, with its cost, its tokens
and the policy decisions that were applied to it.

### Step 4 — Connect a coding agent or the CLI

```bash
curl http://127.0.0.1:3000/api/v1/cli/install.sh | sh
ssai login http://127.0.0.1:3000/portal/t/<your organisation>
ssai provision
```

On Windows, install it from PowerShell instead (`irm http://127.0.0.1:3000/api/v1/cli/install.ps1 |
iex`); `login` and `provision` are the same.

`provision` writes the configuration for whichever client you pick, with a key of its own. Everything
the CLI needs is discovered from the console address you give it.

One limitation on the loopback setup: `ssai run --sandbox` requires the gateway to be
reachable over HTTPS, because the sandbox works by intercepting encrypted connections. Unsandboxed
`ssai run` works as normal; for the sandbox, install with TLS as below.

### Going beyond your own machine

The default install listens on a loopback address only, which is what makes it safe to serve over
plain HTTP. Serving that same setup on a network address would put sign-in credentials in the clear,
so the installer never does.

To serve real users, give it hostnames and a TLS mode (the five routes and the modes are in
*TLS modes*, § B):

```bash
sh streamscopeai.sh --tls acme --set STOWAGE_ACME_EMAIL=ops@example.com \
  --domains console=admin.example.com,api=api.example.com,gateway=gateway.example.com,metrics-api=metrics-api.example.com,metrics-gateway=metrics-gw.example.com
```

That serves every route over HTTPS on ports 80 and 443 (`--http-port` / `--https-port` move them),
and keeps the protection the loopback setup relaxes: session cookies are secure-only. Point DNS for
every name at the host first, so the certificate request can be answered. `--tls internal` gives a
self-signed setup for trying TLS out; `--tls byo --cert … --key …` takes your own certificate.

Loopback and TLS are two different installs: moving between them is a new install in another
directory. Between TLS modes, a re-run moves (below).

### Day-2 — Change settings, upgrade and roll back

The install keeps its own installer, `streamscopeai/ssai-stow`. Run it again on the directory to
change what was recorded — it changes what it is given, and only that, then brings the stack up again
and runs provisioning:

```bash
streamscopeai/ssai-stow status --dir ./streamscopeai                  # release, URLs, settings, services
streamscopeai/ssai-stow --dir ./streamscopeai --set API_DOCS_PUBLIC=false
streamscopeai/ssai-stow --dir ./streamscopeai --ports gateway=8180
streamscopeai/ssai-stow --dir ./streamscopeai --tls byo --cert cert.pem --key key.pem
```

Each change is logged; the values it replaced are kept, so a re-run giving them back undoes it.
`--address`, `--registry` and `--registry-ca` are fixed at the first install. When you move a port or
a domain, update the same URL in the console under **Settings → Defaults**.

The installer also runs the stack's services one at a time — `ps`, `logs <service>`, `restart`,
`stop` and `start <service>`, `exec <service> -- <command>` — and `uninstall` removes the stack's
containers, keeping its data and the install directory for a later install. `uninstall --data` also
deletes the data **and the install directory** — its secrets (the encryption key included), the
snapshots and the release kept for rollback: copy off what you want to keep first.

**Network tuning.** Each container takes the host's network settings. The host itself is not
changed: the install says in one line when its settings differ from what the gateway's load
wants. `streamscopeai/ssai-stow tune` shows the difference, and `tune --apply` (as root, asked
first) writes it; `--revert` puts the host back. The release tunes for a host serving the gateway's
many connections (the `network` profile); on a host shared with other work, a re-run adding
`--tune-profile default` asks for less (`--tune-profile release` returns to the release's own).

**Upgrade** with the new release's installer, or name the version:

```bash
streamscopeai/ssai-stow upgrade --dir ./streamscopeai --version <release>
# or: docker run --rm <registry>/streamscopeai-installer:latest > streamscopeai.sh && sh streamscopeai.sh upgrade --dir ./streamscopeai
```

`<release>` is the version you are moving to, e.g. `2026.11.1`; read the changelog of every release
between yours and it first — a **BREAKING** entry names what to do around the upgrade. An upgrade checks the release's
signature, pulls its images, and only then dumps the database to `streamscopeai/snapshots/`, keeps the
running release to roll back to, carries every setting forward (asking for anything the new release
introduces), starts the stack and runs provisioning. There is a short interruption while the services
restart: this shape runs one of each service, so there is no rolling update.

If the upgrade does not come up, the most common reason is a database change that could not be
applied. The deployment reports itself unhealthy rather than starting in a half-migrated state, and
each change is applied whole or not at all — so nothing is left half-written. Go back with the
installer the install now keeps:

```bash
streamscopeai/ssai-stow rollback --dir ./streamscopeai
```

**A rollback also works after the database changed.** The previous release reads past database
changes it does not know — including the ones a partly-failed upgrade applied before a later change
failed. The installer checks before doing anything, and refuses when the database carries a change
older releases cannot run on (its release says so in the changelog), pointing you at the snapshot it
took before the upgrade — restore that instead.

Keep the snapshots in `streamscopeai/snapshots/` for as long as you might want to go back, and copy
them off the host.

**A release that starts a new database baseline cannot be upgraded to.** Rarely, a release resets the
database's shape instead of changing it; its changelog entry is marked **BREAKING** and says so.
The data does not carry across it: the new release's `reset-db --new-baseline` wipes it and installs
that release with the install's settings, keeping the host, its keys, certificates and generated
secrets, and provisions it afresh — set the organisation up again in the console. On Docker run the
new release's installer, `streamscopeai/ssai-stow reset-db --new-baseline --dir ./streamscopeai`;
on the VM `sudo ssai-stow reset-db --new-baseline [--version V]` (it writes the new release's
system, and the boot into it does the crossing); on Kubernetes `k8s reset-db --new-baseline`, run by
the new release's installer. With an `external` database the installer does not touch that
database, so take the old release down first (`k8s uninstall`), drop the database and create it
again with § F Step 1's `CREATE DATABASE` — on the PostgreSQL release the new release requires —
and run Step 1's two statements on it again (`ALTER SCHEMA public OWNER TO …`, `GRANT CREATE ON
DATABASE …`; the roles belong to the server and are kept). On a new server, run all of Step 1. Then
install the new release with its installer. The installer refuses an `upgrade` to such a release,
and a `rollback` from it to a release of the previous baseline, before anything changes — on the VM
before it writes the new system — naming `reset-db --new-baseline` as the way across.

`streamscopeai/ssai-stow reset-db --dir ./streamscopeai` takes the install back to its first setup:
it deletes the database and the gateway's buffers (the certificates are kept), starts again and
provisions anew, with new passwords. Nothing is dumped first.

Rotate the signing secret with `streamscopeai/ssai-stow secrets rotate AUTH_SECRET --dir ./streamscopeai`
and its `--stage` / `--finish` passes (see *Rotating `AUTH_SECRET`*, § B).

### Hardening

- **Keep it on loopback, or put it behind TLS.** There is no third option that is safe.
- **Move the credentials off the host.** `credentials.txt` holds the account passwords, an API key
  and the automation keys. Record them wherever you keep secrets and delete the file.
- **Export the secrets.** The encryption key cannot be rotated once provider credentials have been
  stored; it is generated for you and kept in the install directory. Keep an encrypted copy off the
  host: `streamscopeai/ssai-stow secrets export --dir ./streamscopeai --recipient age1…`.
- **Egress is closed by default.** The platform reaches no private network address until the
  platform administrator lists it under **Settings → Egress**, and cloud metadata endpoints are
  refused in every case. List only what you trust (see § E, *Internal-egress posture*).
- **The database port is not published.** Reach it through the deployment when you need to.

### Backups

This shape runs one database on one host, with no standby and no failover: its answer to a lost
database or a lost host is these backups. The same off-host backups as the VM appliance (§ D,
*Backup & restore*), run by the install's own installer:

```bash
sudo streamscopeai/ssai-stow backup config --dir ./streamscopeai \
  --destination remote:streamscope --rclone-config rclone.conf --recipient age1… \
  [--schedule daily] [--retention-days 30] [--profile full|config]
sudo streamscopeai/ssai-stow backup verify --dir ./streamscopeai   # writes a probe file to the destination
sudo streamscopeai/ssai-stow backup run --dir ./streamscopeai      # back up now
streamscopeai/ssai-stow backup status|list --dir ./streamscopeai
sudo streamscopeai/ssai-stow restore <backup> --dir ./streamscopeai --identity key.txt
```

Each backup is the database, encrypted to the age public keys given (the private keys stay with
you) as it streams to the rclone destination. The schedule is a systemd timer of the install's own,
set up when the installer runs as root on a host with systemd; elsewhere a backup runs when you run
`backup run`. A restore loads the backup into a database of its own and swaps it in only once the
load succeeded, then brings the stack up and runs provisioning. Every upgrade also dumps the
database to `streamscopeai/snapshots/` first.

Keep the secrets export beside the backups: to rebuild on a new host, install with the decrypted
export (`sh streamscopeai.sh --secrets secrets.yaml`, the same release) — it starts without
provisioning, waiting for your data — then `restore` the backup into it. With `--tls internal`, the new
install keeps the lost one's root, so the clients that trusted it still do. If the database must
survive the loss of a host, run a managed database or CloudNativePG on Kubernetes (§ F, *Backups,
HA, and scaling*).

**Disk space.** On the same root-and-systemd hosts the install also runs the appliance's
disk-pressure watch: every 10 minutes it reads the filesystem holding Docker's data and, past 75 %,
has the platform purge the oldest audit data first; `ssai-stow status` shows the last reading.

**Certificates.** With your own certificate (`--tls byo`), `ssai-stow status` shows its expiry date
and warns from 30 days before it; a certificate whose chain does not verify without `--ca` is
refused at install, so give the full chain (or `--ca`).

### Processor architecture

The published images are built for **x86-64**. On an Apple Silicon or other ARM machine, Docker will
run them through emulation: usable for evaluation, noticeably slower, and the optional
prompt-injection guardrail may not run at all. Use an x86-64 host for anything beyond trying it out.

---

## H. Serving your own models with vLLM

Streamscope forwards to a self-hosted vLLM like any other OpenAI-compatible server. When one engine
is not enough, run **replicas** and add each as an **endpoint** of one upstream server (Admin Guide,
*Replica endpoints*): the gateway pins each conversation to one replica, so that replica's prefix
cache keeps serving the conversation's earlier turns, and moves it to another replica only when its
replica fails.

**Replicas or tensor parallelism.** If the model fits on one GPU, run one vLLM process per GPU and
add each as an endpoint: that gives more total throughput than one process spanning the GPUs, and
the gateway sees each queue on its own. Use tensor parallelism (`--tensor-parallel-size`) when the
model does not fit on one GPU, when long agent contexts need one large KV cache, or for the lowest
per-token latency (it needs a fast GPU interconnect). Do not also enable vLLM's internal data-parallel
load balancer behind the gateway — the gateway cannot see its ranks, so it cannot keep a
conversation on one of them.

**Start every replica the same way.** The gateway treats replicas as one model, so they must answer
to the same name and serve the same weights:

- `--served-model-name <name>` on every replica. Without it the model's name is its weights path,
  which differs between hosts and makes each replica a different model.
- The same weights and the same `--max-model-len`. When replicas report different context windows,
  clients are shown the smallest; the server page flags the difference.
- Tool calling needs `--enable-auto-tool-choice --tool-call-parser <parser>`. Without it the engine
  serves no tools, but the model is assumed to support them unless you turn the capability off on
  the model.
- LoRA adapters (`--enable-lora`, `--lora-modules`) may differ between replicas: an adapter is sent
  only to the replicas that list it.

**Let the gateway reach the model list.** Each replica's `GET /v1/models` must be reachable from the
gateway with the server's credential. An endpoint whose list cannot be read is assumed to serve every
model of its server — fine for identical replicas, wrong for replicas that load different adapters.

**Price the model.** vLLM publishes no prices, so a vLLM model is *unpriced* until you set its rates
(free, or an internal chargeback rate) — and a budget cannot be enforced on an unpriced model.

**Engine metrics are read by default.** For a vLLM server, every gateway replica reads each
endpoint's `/metrics` every few seconds (`QOS_METRICS_POLL_SECS`, default 2) so the server's
dashboard can show the engine's queue, KV cache and throughput — so that path must be reachable from
the gateways. It is read at the engine's root even when the endpoint is an OpenAI-style base URL ending
in `/v1`. Turn it off per server on its **QoS** tab if the port is not reachable; the
tab's **Probe engines** shows what each endpoint answers.

**Capacity, so the gateway can queue instead of the engine.** A saturated engine queues internally,
where the gateway can no longer choose who goes first. Give the server the *Gateway-managed* mode on
its server page (**QoS**), and the gateway holds the overflow itself:

- **Requests in flight per engine** — how many the gateway may have running at one endpoint at
  once, counted by **each gateway replica**: with N replicas an engine can receive N times it, so
  divide the engine's capacity by the replicas (the tab shows how many are connected, and **Probe
  engines** suggests a value once an engine has been seen keeping requests waiting). Start from what
  the engine sustains — vLLM's `--max-num-seqs` is a cap, not a capacity — and lower it if the
  engine still builds a queue. The server's **QoS** tab lists the vLLM settings that decide when an
  engine queues.
- **Engine queue allowed** — how long that replica's own waiting queue may grow before the gateway
  stops sending it more. `0` means "send nothing while anything is waiting there". The gateway reads
  this from the replica's `/metrics`, so that endpoint must be reachable from the gateway — leave it
  unset if it is not, and the in-flight count alone will bound the replica. The read presents the
  server's own credential as a bearer token, so an engine behind a proxy that checks one is
  satisfied; a plain engine ignores it. A proxy that expects some other scheme refuses the read, and
  so does one in front of a server whose models are not routed to any alias yet — in both cases the
  gateway says so in the log instead of letting the silence pass for an engine with nothing queued. A
  reading that stops
  arriving (the engine restarted, the port went away, the path now refuses) expires after three
  polling intervals and the gateway falls back to that count, rather than holding traffic against a
  number nobody is refreshing — and names the endpoint in the log the first time it goes quiet, so a
  bound that has silently stopped applying is something you are told about rather than something you
  have to notice. Several gateway replicas
  reading the same engine share that number, which is what stops them filling it independently.
- Set both on the server for every replica, or override one replica on its own row when a machine is
  smaller or larger than its siblings.

**If something of yours sits in front of Streamscope.** A held request sends nothing to the client
until the gateway dispatches it — up to the deployment's maximum hold (`QOS_QUEUE_TTL_MAX_MS`,
9 minutes unless you change it; the Background class waits up to 2 minutes), *before* the upstream
call starts and on top of the model's own answer time. A reverse proxy, load balancer or CDN of
yours whose idle or read timeout is shorter than that turns a hold into a gateway timeout its caller
cannot tell apart from a dead upstream, and which nothing in Streamscope records. The TLS front end
shipped with the appliance and the Docker deployment sets no such timeout, and the Helm chart sets
ingress-nginx's to 15 minutes (§ F); anything you add in front is yours to raise — or lower
`QOS_QUEUE_TTL_MAX_MS` below it. A replica that is shutting down refuses every held request at once
(the client is told to retry), so a long hold never delays a restart.

**Priority, only if you started vLLM for it.** With the *Engine priority only* mode, or the
*Gateway-managed* mode with "the engines run with --scheduling-policy priority" ticked, the gateway
also tells the engine what each request it hands over is worth. That requires the engine
to run `--scheduling-policy priority`: vLLM's API documents a non-zero priority as an error on a
server that does not, and priority there only reorders what is waiting — it never interrupts a
request already running. Leave it unticked (the default) and the ordering stays entirely the
gateway's, which works on any engine.

**Admission limits.** vLLM's own `--max-num-queued-reqs` / `--max-num-queued-tokens` refuse with
HTTP 503 once its queue is full. The gateway treats that as "this replica is full", moves the
request to another replica if one can serve it, and otherwise holds it — but it is a blunt backstop:
with the capacity settings above, the gateway stops sending long before the engine has to refuse.
