[![Checks](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/checks.yaml/badge.svg)](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/checks.yaml)
[![Dependabot Updates](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/dependabot/dependabot-updates)
[![DNF Integration](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/dnf-integration.yaml/badge.svg)](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/dnf-integration.yaml)
[![Release](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/release.yaml/badge.svg)](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/release.yaml)
[![Release Smoke](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/release-smoke.yaml/badge.svg)](https://github.com/obviousaichicken/zabbix-dnf-plugin/actions/workflows/release-smoke.yaml)

# Zabbix DNF Plugin

A loadable `zabbix-agent2` plugin for package-update monitoring on DNF and APT systems. The historical plugin identity and configuration namespace remain `DNF` / `Plugins.DNF`, while the package-manager-neutral `packages.get` key supports both backends.

The plugin collects:

* Enabled DNF repositories or configured APT binary repositories
* Available package updates
* Security and other update counts on both backends
* Bugfix and enhancement update counts where DNF advisory metadata supports them
* Update counts per repository
* Pending reboot status
* Most recent package update time and result
* Local APT package-index age
* Applicable DNF security advisory IDs, severities, affected updates, known CVEs, and vendor timestamps

The plugin exposes the legacy `dnf.get` payload, the cross-backend `packages.get` payload, and the independently scheduled DNF-only `dnf.advisories.get` payload for dependent items and discovery rules. Advisory collection failures never make either package key fail.

<img width="1905" height="1016" alt="Screenshot From 2026-08-21 20-38-47" src="https://github.com/user-attachments/assets/ea31ef4a-861f-4865-8748-1dcf3f474762" />

<img width="2106" height="634" alt="Screenshot From 2026-08-21 20-39-21" src="https://github.com/user-attachments/assets/cf966977-d3b7-49e6-9b3b-d984cd8b0a97" />

<img width="2202" height="520" alt="Screenshot From 2026-08-21 20-39-53" src="https://github.com/user-attachments/assets/51f4dcac-2fab-4973-816d-c9e225839fc3" />

<img width="2199" height="290" alt="Screenshot From 2026-08-21 20-39-37" src="https://github.com/user-attachments/assets/d891dfe2-7b07-482c-8279-ed0770003751" />

## Install the plugin

The plugin is compatible with `zabbix-agent2` 7.0, 7.2, and 7.4 on the distributions in the [support matrix](#compatibility).

### Automated installation

Run this command:

```bash
curl -fLO https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/latest/download/install.sh && sudo sh install.sh
```

The installer detects the supported DNF or APT backend, downloads and verifies the same plugin binary and configuration, runs read-only package-manager preflight checks as `zabbix`, validates the Agent 2 configuration, restarts the service, and tests the appropriate item keys. The DNF branch preserves repository-key bootstrap and SELinux handling. The APT branch requires package indexes to have been populated already and never runs `apt-get update` for the operator.

### Manual installation

```bash
# Download the latest binary and its SHA-256 checksum from GitHub Releases:
curl -fL -o zabbix-dnf-plugin https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/latest/download/zabbix-dnf-plugin

# Download the checksum
curl -fL -o zabbix-dnf-plugin.sha256 https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/latest/download/zabbix-dnf-plugin.sha256

# Verify binary
sha256sum --check zabbix-dnf-plugin.sha256

# Install the binary
sudo install -D -m 0755 zabbix-dnf-plugin /usr/sbin/zabbix-agent2-plugin/zabbix-dnf-plugin

# Create config file
sudo sh -c 'cat > /etc/zabbix/zabbix_agent2.d/plugins.d/dnf.conf' <<'EOF'
Plugins.DNF.System.Path=/usr/sbin/zabbix-agent2-plugin/zabbix-dnf-plugin
Plugins.DNF.System.Capacity=1
PluginTimeout=30
EOF

# Set config file rights
sudo chmod 0644 /etc/zabbix/zabbix_agent2.d/plugins.d/dnf.conf

# On systems with SELinux, apply the default contexts for the installation paths
sudo restorecon -Rv /usr/sbin/zabbix-agent2-plugin /etc/zabbix/zabbix_agent2.d/plugins.d/dnf.conf

# Confirm that the zabbix user can query DNF on a DNF host
sudo -u zabbix dnf -q repolist
sudo -u zabbix dnf -q repoquery --upgrades

# Or confirm read-only APT access on a Debian/Ubuntu host. Populate indexes as
# root first if this host has never run apt-get update.
sudo -u zabbix apt-get indextargets
sudo -u zabbix dpkg-query --show
sudo -u zabbix apt-cache policy dpkg:$(dpkg --print-architecture)

# Restart the agent and check that it started correctly
sudo systemctl restart zabbix-agent2
systemctl status zabbix-agent2
```

`dnf.conf` intentionally omits a backend setting. New binaries default to automatic detection, and the same file therefore remains readable by older plugin versions. See [Backend selection and overrides](#backend-selection-and-overrides) before adding an override.

### Troubleshooting

```bash
# Test the neutral item on either backend
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t packages.get

# Test the legacy DNF item on a DNF host
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t dnf.get

# Test the independently scheduled advisory item on a DNF host
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t dnf.advisories.get

# Run the legacy collector directly on a DNF host without the Agent 2 protocol
sudo /usr/sbin/zabbix-agent2-plugin/zabbix-dnf-plugin --test

# Check for SELinux policy denials
sudo ausearch -m AVC -ts recent
```

## Import the Zabbix template

Download `template-dnf-by-zabbix-agent2.yaml` from the GitHub release. Despite its compatibility-preserving filename, this single export contains the DNF and APT templates, each in passive and active variants.

In Zabbix, go to **Data collection > Templates > Import**, import the downloaded file, and link the appropriate package-manager and collection variant to each host running the plugin. Link exactly one of the four templates to a host.

Each template creates the required host-level monitoring items, repository discovery, and alerts automatically. DNF per-advisory discovery is present but disabled by default to avoid unplanned object cardinality.

### DNF template details

**Macros**

|Name|Description|Default|
|----|-----------|-------|
|{$DNF.ADVISORY.NODATA.TIME}|Time without a successful advisory collection before an availability problem is raised.|`2h`|
|{$DNF.ADVISORY.LLD.CRITICAL}|Enable per-advisory discovery for Critical advisories. Values other than exactly `0` or `1` fail discovery.|`0`|
|{$DNF.ADVISORY.LLD.IMPORTANT}|Enable per-advisory discovery for Important advisories. Values other than exactly `0` or `1` fail discovery.|`0`|
|{$DNF.ADVISORY.LLD.MODERATE}|Enable per-advisory discovery for Moderate advisories. Values other than exactly `0` or `1` fail discovery.|`0`|
|{$DNF.ADVISORY.LLD.LOW}|Enable per-advisory discovery for Low advisories. Values other than exactly `0` or `1` fail discovery.|`0`|
|{$DNF.ADVISORY.LLD.UNKNOWN}|Enable per-advisory discovery for Unknown-severity advisories. Values other than exactly `0` or `1` fail discovery.|`0`|
|{$DNF.ADVISORY.UPDATE.INTERVAL}|Interval between independent DNF advisory collections.|`1h`|
|{$DNF.COLLECTION.DURATION.MAX}|Maximum acceptable average collection duration, in seconds.|`20`|
|{$DNF.COLLECTION.DURATION.WINDOW}|Evaluation window for the average collection duration.|`30m`|
|{$DNF.NODATA.TIME}|Time without a successful collection before an availability problem is raised.|`30m`|
|{$DNF.SECURITY.ADVISORY.MAX.AGE}|Maximum acceptable age of the oldest known vendor timestamp for an applicable advisory.|`7d`|
|{$DNF.SECURITY.CRITICAL.MIN}|Minimum number of Critical advisories that raises a Disaster problem.|`1`|
|{$DNF.SECURITY.IMPORTANT.MIN}|Minimum number of Important advisories that raises a High problem when no Critical threshold is met.|`1`|
|{$DNF.SECURITY.MIN}|Minimum number of security updates that raises a problem.|`1`|
|{$DNF.SECURITY.UNKNOWN.MAX}|Maximum accepted number of advisories or affected package updates with Unknown severity.|`0`|
|{$DNF.UPDATE.INTERVAL}|Interval between complete DNF collections.|`15m`|

**Items**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Get update data|Collects the complete package, repository, advisory, reboot, and update-history payload. The raw JSON is not retained because dependent items extract the monitored values.|Zabbix agent|dnf.get|
|DNF: Get advisory data|Collects applicable DNF security advisories independently from package-update monitoring.|Zabbix agent|dnf.advisories.get, interval `{$DNF.ADVISORY.UPDATE.INTERVAL}`, history disabled, 30-second timeout|
|DNF: Advisory discovery data|Validates completeness and the five selection macros, then projects compact records for discovery. It becomes unsupported on invalid or incomplete input instead of publishing a false empty list.|Dependent item|dnf.advisory.discovery.data, history disabled|
|DNF: Collection complete|Indicates whether the plugin completed every required DNF query. Failed collections make the master item unsupported and are also detected by the no-data condition.|Dependent item|dnf.collection.complete|
|DNF: Collection duration|Time spent collecting the complete DNF payload, in seconds.|Dependent item|dnf.collection.duration|
|DNF: Advisory classification complete|Indicates that all advisory categories were classified successfully. Strict classification failures make the master collection fail instead of publishing partial category counts.|Dependent item|dnf.classification.complete|
|DNF: Updates pending total|Total number of available package updates across all enabled repositories.|Dependent item|dnf.updates|
|DNF: Enabled repositories|Number of enabled DNF repositories included in the collection.|Dependent item|dnf.repositories|
|DNF: Updates pending|Indicates whether one or more package updates are available.|Dependent item|dnf.updates.pending|
|DNF: Reboot pending|Indicates whether installed reboot-sensitive packages or a newer installed kernel require the host to be rebooted.|Dependent item|dnf.reboot.pending|
|DNF: Updates pending security|Number of available package updates classified by repository advisory metadata as security updates.|Dependent item|dnf.updates.security|
|DNF: Updates pending bugfix|Number of available package updates classified by repository advisory metadata as bug fixes.|Dependent item|dnf.updates.bugfix|
|DNF: Updates pending enhancement|Number of available package updates classified by repository advisory metadata as enhancements.|Dependent item|dnf.updates.enhancement|
|DNF: Updates pending other|Number of available package updates with no supported advisory category. This can include missing or unrecognized advisory metadata and does not necessarily mean non-security updates.|Dependent item|dnf.updates.other|
|DNF: Last update result|Result of the most recent completed DNF transaction that upgraded a package: 0 means not recorded, 1 means success, and 2 means failed.|Dependent item|dnf.last_update.result|
|DNF: Last update time|Unix timestamp of the most recent completed DNF transaction that upgraded a package. No value is stored when no such transaction exists.|Dependent item|dnf.last_update.timestamp|
|DNF: Advisory collection health|Independent completion and duration telemetry.|Dependent items|dnf.advisory.collection.complete, dnf.advisory.collection.duration|
|DNF: Advisory metadata completeness|Reports whether detail, CVE, and true issue-date metadata are authoritative.|Dependent items|dnf.advisory.details.complete, dnf.advisory.cves.complete, dnf.advisory.issue_dates.complete|
|DNF: Advisory and CVE totals|Counts unique advisory IDs and known CVE IDs.|Dependent items|dnf.advisory.total, dnf.advisory.cves|
|DNF: Advisories by severity|Counts Critical, Important, Moderate, Low, and Unknown advisory IDs.|Dependent items|dnf.advisory.critical, dnf.advisory.important, dnf.advisory.moderate, dnf.advisory.low, dnf.advisory.unknown|
|DNF: Affected updates by severity|Counts unique pending package updates once at their highest linked advisory severity.|Dependent items|dnf.advisory.packages.critical, dnf.advisory.packages.important, dnf.advisory.packages.moderate, dnf.advisory.packages.low, dnf.advisory.packages.unknown|
|DNF: Oldest advisory vendor time|Reports the oldest preferred vendor timestamp, its age, and whether its basis is `issued`, `updated`, or `none`.|Dependent items|dnf.advisory.oldest.timestamp, dnf.advisory.oldest.age, dnf.advisory.oldest.basis|

**Triggers**

|Name|Description|Expression|Severity|Dependencies and additional info|
|----|-----------|----------|--------|--------------------------------|
|DNF: Collection is unavailable|DNF update data is stale or unavailable until collection succeeds.|`last(/DNF by Zabbix agent 2/dnf.collection.complete)=0 or nodata(/DNF by Zabbix agent 2/dnf.collection.complete,{$DNF.NODATA.TIME})=1`|High||
|DNF: Collection is slow|The average collection duration is approaching the hard plugin and item timeout. Check repository availability and DNF performance.|`avg(/DNF by Zabbix agent 2/dnf.collection.duration,{$DNF.COLLECTION.DURATION.WINDOW})>{$DNF.COLLECTION.DURATION.MAX}`|Warning||
|DNF: Reboot is required|A reboot is required to complete package updates.|`last(/DNF by Zabbix agent 2/dnf.reboot.pending)=1`|Warning||
|DNF: Security updates are available|One or more security updates are available.|`last(/DNF by Zabbix agent 2/dnf.updates.security)>={$DNF.SECURITY.MIN}`|High||
|DNF: Last package update failed|The most recent package update transaction did not complete successfully.|`last(/DNF by Zabbix agent 2/dnf.last_update.result)=2`|Warning||
|DNF: Advisory collection is unavailable|The independent advisory item is stale or unsupported.|`last(.../dnf.advisory.collection.complete)=0 or nodata(...,{$DNF.ADVISORY.NODATA.TIME})=1`|High||
|DNF: Critical security advisories are applicable|The Critical advisory threshold is met.|`last(.../dnf.advisory.critical)>={$DNF.SECURITY.CRITICAL.MIN}`|Disaster||
|DNF: Important security advisories are applicable|The Important threshold is met while the Critical threshold is not.|`last(.../dnf.advisory.critical)<{$DNF.SECURITY.CRITICAL.MIN} and last(.../dnf.advisory.important)>={$DNF.SECURITY.IMPORTANT.MIN}`|High|Mutually exclusive with the Critical problem.|
|DNF: Applicable security advisory is old|The oldest known vendor timestamp exceeds the configured age.|`last(.../dnf.advisory.oldest.age)>{$DNF.SECURITY.ADVISORY.MAX.AGE}`|Warning||
|DNF: Security advisory severity is unknown|Unknown advisory or affected-package severity exceeds the configured maximum.|Checks both `dnf.advisory.unknown` and `dnf.advisory.packages.unknown`.|High||
|DNF: Advisory metadata is incomplete|Detail, CVE, or true issue-date metadata is incomplete.|Checks all three advisory completeness items.|Warning|Expected on DNF4 with the bounded list-only strategy.|
|DNF: Security package updates lack advisory objects|The package classifier reports more security updates than the advisory collector can link.|Compares `dnf.updates.security` with the sum of all five advisory package-severity counts.|Warning||

**LLD rule DNF: Repository discovery**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Repository discovery|Discovers enabled DNF repositories. Items for repositories that disappear are disabled immediately and retained for 30 days before deletion.|Dependent item|dnf.repository|

**Item prototypes for DNF: Repository discovery**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Repository [{#REPO_NAME}]: Available update count|Number of available package updates from repository {#REPO_NAME} ({#REPO_ID}).|Dependent item|dnf.repository.updates["{#REPO_ID}"]|
|DNF: Repository [{#REPO_NAME}]: Pending package details|Comma-separated NEVRA identifiers for packages with available updates from repository {#REPO_NAME} ({#REPO_ID}). The value is blank when there are no pending packages.|Dependent item|dnf.repository.update.details["{#REPO_ID}"]|

#### Opt-in per-advisory discovery

Per-advisory discovery is an optional layer on top of the host-level advisory summaries. All five severity macros default to `0`, so importing and linking the template produces no discovered advisory items or triggers. Summary-only users should leave them unchanged; they still receive every advisory count, age, completeness, and host-level alert described above.

Discovery accepts data only when the collection and all detail, CVE, and issue-date completeness flags are true. This normally limits it to complete DNF5 results. Enabling it on DNF4, or during an incomplete DNF5 response, makes the projection unsupported and preserves existing discovered problem state rather than returning an empty list. A valid later response that no longer contains an advisory publishes presence `0`; the trigger recovers before the objects are disabled after one day and deleted after 30 days.

Each selected advisory creates five item instances and one trigger instance:

|Prototype|Value|Key|
|---------|-----|---|
|Presence|`1` while applicable, then `0` on a valid disappearance.|dnf.advisory.presence[{#ADVISORY_SAFE_ID}]|
|Vendor timestamp|Unix issue timestamp from the complete vendor record.|dnf.advisory.vendor.timestamp[{#ADVISORY_SAFE_ID}]|
|Affected package count|Number of unique pending package NEVRAs.|dnf.advisory.packages.count[{#ADVISORY_SAFE_ID}]|
|Affected package list|Sorted JSON array of pending package NEVRAs.|dnf.advisory.packages.list[{#ADVISORY_SAFE_ID}]|
|CVE list|Sorted JSON array of known CVE IDs.|dnf.advisory.cves.list[{#ADVISORY_SAFE_ID}]|

The trigger priority is Disaster for Critical, High for Important, Warning for Moderate, Information for Low, and High for Unknown. The actual advisory ID remains visible in item names, trigger names, and tags. Keys contain only a lossless lowercase-hex encoding of its UTF-16 code units; quote and backslash characters therefore cannot alter key syntax. IDs longer than 256 code units fail discovery explicitly instead of being truncated.

If `N` advisories match the enabled severity macros on a host, budget for `5N` item instances and `N` trigger instances, plus the fixed projection item and discovery rule. There is no separate advisory-count cutoff before the 8 MiB payload guard, so enable only severities whose object-level history and problems are operationally useful. Critical-only or Critical-plus-Important is the conservative starting point.

To enable discovery on a DNF5 host:

1. Confirm that `dnf.advisories.get` is supported and that `dnf.advisory.collection.complete`, `dnf.advisory.details.complete`, `dnf.advisory.cves.complete`, and `dnf.advisory.issue_dates.complete` all report `1`.
2. Override the desired host or template macros from exactly `0` to exactly `1`; for example, set `{$DNF.ADVISORY.LLD.CRITICAL}` to `1`.
3. Run or wait for `DNF: Advisory discovery`, then check discovered-object counts before enabling more severities.

To turn the layer off without rolling back the template, restore all five macros to `0`. The next valid advisory payload returns an intentional empty discovery set, presence items recover to zero during the one-day grace, and Zabbix removes the disabled objects after 30 days. For a full version rollback, follow the template-before-binary order below; no plugin or package-manager data migration is needed.

### APT template details

The APT template uses `packages.get` as its master item. It monitors the common collection, repository, update, reboot, and best-effort history fields plus the age of the oldest local binary package index used in the collection.

**Macros**

|Name|Description|Default|
|----|-----------|-------|
|{$APT.COLLECTION.DURATION.MAX}|Maximum acceptable average collection duration, in seconds.|`20`|
|{$APT.METADATA.AGE.MAX}|Maximum acceptable age of the oldest local APT binary index.|`2d`|
|{$APT.NODATA.TIME}|Time without a successful collection before an availability problem is raised.|`30m`|
|{$APT.SECURITY.MIN}|Minimum number of positively identified security updates that raises a problem.|`1`|
|{$APT.UPDATE.INTERVAL}|Interval between complete APT collections.|`15m`|

**Items and discovery**

|Purpose|Keys|
|-------|----|
|Collection health|`apt.collection.complete`, `apt.collection.duration`|
|Repository and update totals|`apt.repositories`, `apt.updates`, `apt.updates.pending`|
|Supported classifications|`apt.updates.security`, `apt.updates.other`|
|Host state and history|`apt.reboot.pending`, `apt.last_update.timestamp`, `apt.last_update.result`|
|Cached-index freshness|`apt.metadata.refreshed`, `apt.metadata.age`|
|Repository discovery|`apt.repository`, with per-repository count and package-detail prototypes|

Pending package details use the lossless Debian identifier `name:architecture=full-version`. The APT template deliberately has no bugfix or enhancement items because APT does not provide those classifications through this collector. It also has no failed-history trigger because retained APT history is best effort.

The APT alerts cover unavailable or slow collection, pending security updates, a required reboot, and stale package indexes. An update classified as `other` was not positively identified as coming from a trusted official Debian, Ubuntu, or Ubuntu ESM security pocket; `other` is not proof that the update has no security impact.

## Compatibility

All listed distributions are supported on Linux x86_64 and exercised in CI:

|Backend|Distribution versions|
|-------|---------------------|
|DNF|RHEL/UBI 8, 9, and 10; Fedora 43 and 44; Rocky Linux 9 and 10; AlmaLinux 9 and 10; CentOS Stream 9 and 10|
|APT|Debian 12 and 13; Ubuntu 22.04, 24.04, and 26.04|

The plugin is compatible with every currently released `zabbix-agent2` version in the 7.0, 7.2, and 7.4 branches.

All three branches use the same plugin binary.

DNF reboot status is determined from reboot-sensitive RPM install times and installed kernel packages compared with the running kernel. The plugin supports DNF4 and DNF5 without depending on an optional DNF reboot-detection plugin. APT reboot status follows `/run/reboot-required`.

### DNF advisory semantics and limits

`dnf.advisories.get` is deliberately separate from `dnf.get` and `packages.get`. Package snapshots normally run every 15 minutes, while advisory detail runs hourly and has its own failure, duration, no-data, and 8 MiB payload guards. The collector never runs a command per advisory:

* DNF4 runs one bounded `updateinfo list --updates --security` command after its version probe. Cross-version timing showed that adding the bulk detail command could exceed the 30-second Agent 2 deadline, so titles, CVEs, and dates are intentionally incomplete. Advisory ID, severity, and applicable package relationships remain authoritative.
* DNF5 runs one JSON list and one JSON info command after its version probe. The list is authoritative for applicability; info data enriches only matching list records, so source, debug, other-architecture, and historical package builds cannot enter the result.

The schema-version-1 summary uses these counting rules:

* `summary.advisories` and `advisories_by_severity` count unique advisory IDs.
* `package_updates_by_severity` counts unique pending NEVRAs. When several advisories affect one update, that package is counted once at the highest severity: Critical, Important, Moderate, Low, then Unknown.
* `summary.unique_cves` is deduplicated. It is authoritative only when `metadata.cves_complete` is true; zero with an incomplete flag does not mean that no CVE applies.
* Unknown or new vendor severity spellings remain `unknown`; they are never silently downgraded to Low.
* Issue and update timestamps are normalized to UTC. A true issue date is preferred; otherwise an available Updated timestamp is used and the summary basis is `updated`. Missing timestamps remain `null`, and future timestamps produce age zero.

DNF5 prefers structured CVE references. Some vendor JSON labels CVE-bearing references as Bugzilla records, so the collector applies only the strict `CVE-YYYY-NNNN...` token extractor as a fallback and never invents a URL. Descriptions are discarded after CVE extraction. Normal fixture payloads are well below the 64 KiB portability target; command output and the final advisory payload fail explicitly rather than truncating at 8 MiB.

A compact DNF4 result therefore looks like:

```json
{
  "metadata": {
    "details_complete": false,
    "cves_complete": false,
    "issue_dates_complete": false
  },
  "summary": {
    "advisories": 1,
    "unique_cves": 0,
    "oldest_vendor_timestamp": null,
    "oldest_vendor_timestamp_basis": "none"
  },
  "advisories": [{
    "id": "RLSA-2026:22314",
    "severity": "moderate",
    "cve_ids": [],
    "affected_update_nevras": ["openssl-libs-1:3.5.5-3.el10_2.x86_64"]
  }]
}
```

On DNF5 the same fields are present, while completeness is normally true and records also contain `title`, `issued_at`, structured known CVEs, and only the applicable binary NEVRAs. Arrays are always JSON arrays, never `null`.

### Backend selection and overrides

With no override, `Plugins.DNF.Backend` defaults internally to `auto`. Auto detection reads `/etc/os-release`: Debian/Ubuntu families select APT, and recognized Fedora/RHEL families select DNF. Detection fails closed when the family is ambiguous or unsupported, or when required commands are missing. The automated installer separately enforces the exact distribution-version support matrix above.

An administrator can force a backend in the plugin configuration when testing a controlled image:

```ini
Plugins.DNF.Backend=dnf
# or
Plugins.DNF.Backend=apt
```

Accepted values are exactly `auto`, `dnf`, and `apt`. A forced backend bypasses family detection but still validates all required command paths. Leave the line absent for normal installations and remove it before rolling back to a binary that predates backend support.

### APT cache semantics and limitations

APT collection is read-only. It uses the installed-package database and locally cached package indexes; it does not contact mirrors, download packages, acquire package-manager locks, or run `apt-get update`. Consequently, a successful collection proves that local metadata was readable, not that a mirror is currently reachable.

The payload reports the oldest modification time across every participating downloaded binary index as `metadata.refreshed_at` and its age as `metadata.age_seconds`. Missing or unreadable participating indexes fail the collection. Old-but-readable indexes remain a valid collection so the template can raise its stale-metadata warning. Schedule `apt-get update` separately according to local policy.

APT security classification is intentionally conservative. Only trusted, recognized official security pockets are counted as security; all remaining candidates are `other`. Bugfix and enhancement capabilities are reported as unsupported. Update history depends on bounded retained `/var/log/apt/history.log*` data and is therefore best effort. Reboot detection uses only `/run/reboot-required`.

## Upgrade and rollback

### Upgrade

Run the current automated installer again, verify `dnf.advisories.get` on DNF hosts, and then import the current template for the host's backend. Upgrade the binary before the template: a new binary remains fully compatible with the old DNF template, while importing the new template first leaves only its new advisory master unsupported until the binary is upgraded. The installer replaces the binary and `dnf.conf` only after verifying the downloaded checksum and validates Agent 2 before restarting it.

Existing DNF installations require no migration: `dnf.get`, `packages.get`, all earlier DNF template item keys and UUIDs, and the configuration namespace retain their meanings. `dnf.advisories.get` and its host-level summary items are additive. Keep backend selection on `auto` unless a deliberate override is required.

### Rollback

Use the binary, checksum, configuration, and template from the same earlier release tag. Roll back the template first, then the binary: the new binary safely serves the old template, whereas an old binary cannot serve the new advisory master. If an emergency binary-first rollback is unavoidable, package monitoring remains compatible but the new `dnf.advisories.get` master and its dependent advisory items become unsupported until the matching old template is restored.

For example, download the selected tagged assets, verify the checksum, stop Agent 2, replace the plugin binary and configuration, then restart and test `dnf.get`:

```bash
release=vX.Y.Z
base_url="https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/download/${release}"
curl -fLO "${base_url}/zabbix-dnf-plugin"
curl -fLO "${base_url}/zabbix-dnf-plugin.sha256"
sha256sum --check zabbix-dnf-plugin.sha256
curl -fL -o dnf.conf "${base_url}/dnf.conf"

sudo systemctl stop zabbix-agent2
sudo install -m 0755 zabbix-dnf-plugin /usr/sbin/zabbix-agent2-plugin/zabbix-dnf-plugin
sudo install -m 0644 dnf.conf /etc/zabbix/zabbix_agent2.d/plugins.d/dnf.conf
sudo systemctl start zabbix-agent2
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t dnf.get
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t packages.get
```

Review and remove any explicit `Plugins.DNF.Backend` line before starting a binary that predates backend support. Import the template shipped with the selected release using your normal change process. Rolling back to a DNF-only release stops APT monitoring; it does not alter packages or APT metadata on the host.

## DNF advisory implementation handoff

The advisory feature is intentionally bounded and independently operable:

* `internal/dnf/advisory_types.go` and `nevra.go` define severity, reference, timestamp, and package identity semantics shared by DNF4 and DNF5.
* `internal/dnf/advisory_dnf4.go` implements the measured list-only strategy. Its detail parser preserves and fuzzes the captured vendor format contract but is not invoked as a subprocess.
* `internal/dnf/advisory_dnf5.go` strictly supports the object/string-timestamp and array/integer-timestamp JSON families, rejects malformed JSON, and reconciles details against the applicable list.
* `internal/results/advisories.go` deduplicates IDs, CVEs, references, and package relationships; applies highest-severity precedence; validates count and timestamp invariants; and enforces the final payload cap.
* `template-dnf-by-zabbix-agent2.yaml` keeps the package master unchanged and adds an hourly advisory master with passive/active parity, host-level summary triggers, and default-off per-advisory discovery.
* The discovery projection validates every selection macro and completeness flag before producing records. Lossless hex identifiers are the only repository-derived values used in prototype keys; valid disappearance, invalid input, and one-day recovery behavior are deterministic fixtures.
* Existing CI rows exercise all three keys across every supported Agent 2 protocol version and DNF image. Template CI checks UUIDv4 uniqueness and preservation, passive/active parity, master links, preprocessing, trigger logic, executable discovery scenarios, and an idempotent Zabbix 7.0 import.

Operationally, investigate `dnf.advisory.collection.complete` before interpreting zero counts, and interpret CVE/date fields only with their corresponding completeness items. The existing `DNF: Security updates are available` trigger remains the compatibility fallback for old binaries and Moderate/Low-only situations; the Critical and Important advisory triggers add severity-aware escalation without replacing it.

### Release-planning evidence checklist

The implementation has a bounded verification path that should remain green before a release tag is created:

* `go test ./...`, `go test -race ./...`, `go vet ./...`, vulnerability scanning, shell checks, and workflow lint cover the binary and automation.
* Golden results, malformed fixtures, fuzz seeds, a 1,000-record stress case, and the 8 MiB failure case cover collector and aggregation contracts.
* The Agent 2 protocol matrix runs `dnf.get`, `packages.get`, and `dnf.advisories.get` on every declared 7.0, 7.2, and 7.4 version without adding advisory-only rows.
* The existing live DNF rows cover all eleven supported distribution variants and enforce the 30-second advisory timeout. The existing APT rows cover all five supported distributions and prove advisory work did not change `packages.get`.
* Template validation locks every pre-existing UUID, passive/active parity, all master links and trigger expressions, disabled LLD defaults, severity overrides, safe keys, appearance/disappearance, invalid macros, and incomplete-payload behavior.
* The template-only Zabbix 7.0 gate imports the combined DNF/APT export twice sequentially, proving schema validity and idempotency without creating a version matrix.
* Upgrade evidence covers a new binary with the old template and an old binary with the new template; only the additive advisory key is unsupported in the latter order.

Creating a tag, publishing a GitHub Release, deploying a production canary, and importing into a user-managed Zabbix system remain explicit release-operator actions. None is performed by the implementation or template-validation workflow.

### Known advisory limitations

* DNF4 deliberately uses list-only advisory collection to stay within the Agent 2 deadline. Its advisory/package relationships and severities are usable for summaries, but detail, CVE, and issue-date flags remain incomplete, so per-advisory discovery is unavailable.
* DNF5 accepts only the explicitly supported 5.2 and 5.3-or-newer JSON families. Structurally malformed or unknown top-level data fails; it never falls back to ambiguous text parsing.
* Results describe advisories applicable through the host's currently enabled repository metadata. They are not an exploitability score, proof of reachability, or replacement for a vulnerability-management policy.
* CVE counts and lists include vendor identifiers the collector can establish. An incomplete flag means zero is not authoritative; descriptions and unrelated references are intentionally excluded from the payload.
* Advisory data normally refreshes hourly. Repository freshness and mirror reachability remain outside this key, and APT has no per-advisory equivalent.
* Object-level monitoring has deliberate cardinality cost: five items and one trigger per selected advisory. The template supplies severity selection rather than an arbitrary record-count truncation, and oversized data fails explicitly.
* Prototype keys support advisory IDs up to 256 UTF-16 code units. Longer IDs make discovery unsupported while host-level summaries continue independently.

## APT implementation handoff

The completed APT feature boundary is intentionally narrow:

* `packages.get` is the stable schema-version-1 key for both DNF and APT; legacy `dnf.get` remains DNF-only and unchanged.
* `internal/apt` owns strict deb822, installed-package, policy, repository, history, reboot-marker, batching, and bounded-output handling. It invokes only the read-only commands documented below.
* The APT objects in `template-dnf-by-zabbix-agent2.yaml` have fresh UUIDs, passive/active parity, and use package `identifier` values for repository details.
* `install.sh` selects only the declared Debian/Ubuntu versions for APT and otherwise preserves the DNF branch.
* Pull-request CI exercises five raw and installed APT distributions; the template job imports the combined export twice and checks UUIDv4, parity, and master references.

The deliberate gaps are also part of the contract: no automatic metadata refresh, no APT bugfix/enhancement claims, no mirror-health claim, no full APT Compose lab, and no migration requirement for existing DNF users.

## Development

The `.dev/docker-compose.yaml` file spins up a complete Zabbix DNF development lab. APT distribution coverage stays in the restrained integration matrix rather than duplicating the Compose lab.

The agent images use explicit distribution tags rather than following moving `latest` tags:

| Agent | Image tag |
| --- | --- |
| UBI 8 | `8.8` |
| UBI 9 | `9.4` |
| UBI 10 | `10.0` |
| Fedora 43 | `43` |
| Fedora 44 | `44` |
| Rocky Linux 9 | `9` |
| Rocky Linux 10 | `10` |
| AlmaLinux 9 | `9` |
| AlmaLinux 10 | `10` |
| CentOS Stream 9 | `stream9` |
| CentOS Stream 10 | `stream10` |

Each DNF lab image runs `install.sh` during its build, including checksum, DNF preflight, and configuration validation. Existing live integration rows then run `dnf.get`, `packages.get`, and `dnf.advisories.get` as `zabbix`; the advisory item must finish below 30 seconds. The reusable integration workflow separately builds installed-Agent images for all five supported APT distributions and runs `packages.get` as `zabbix`.

```bash
docker compose -f .dev/docker-compose.yaml up --build
```

The `zbx70_bootstrap` service waits for the Zabbix API and imports or updates all four variants from the combined template file. The local Compose lab intentionally provisions DNF hosts only: eleven passive distribution hosts plus active-only UBI 9 and Fedora 44 hosts exercise DNF4 and DNF5. The bootstrap queues an initial collection for each passive host; active collections are scheduled and submitted by the agents.

## Build from source

Building the plugin requires Go 1.27.0 or newer.

```bash
CGO_ENABLED=0 go build -o zabbix-dnf-plugin ./cmd/agent
```

## Commands executed

### DNF

The DNF backend uses the host's enabled repositories and their configured URLs.

```bash
# List enabled repositories
dnf --assumeno -q repolist

# Query the latest available updates, optionally by advisory type
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' repoquery --upgrades [--security|--bugfix|--enhancement] --latest-limit=1 --queryformat '%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{repoid}\n'

# Detect the installed DNF version
dnf --assumeno --version

# DNF4: list applicable security advisory/package relationships
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' updateinfo list --updates --security

# DNF5: list applicable relationships and read bulk detail as JSON
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' advisory list --updates --security --json
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' advisory info --updates --security --json

# List DNF transactions.
dnf --assumeno -q history list [--json]

# Inspect one DNF transaction
dnf --assumeno -q history info TRANSACTION_ID [--json]

# Read package installation times for reboot detection
rpm -qa --qf '%{NAME}|%{INSTALLTIME}\n'

# List installed kernels for reboot detection
rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}\n' 'kernel*'

# Read the running kernel version
uname -r
```

The update query runs once without an advisory flag and once for each listed classification. Advisory collection is separate and fixed at one version probe plus one DNF4 command or two DNF5 commands. JSON history output is used when supported by DNF5.

### APT

The APT backend runs only read-only queries against the installed-package database and existing local indexes:

```bash
# Enumerate downloaded binary package indexes and repository metadata
apt-get indextargets

# Snapshot installed packages and their exact architecture/version identity
dpkg-query --show '--showformat=${binary:Package}|${Architecture}|${Version}|${db:Status-Status}\n'

# Resolve installed/candidate versions, priorities, phasing, and exact sources
apt-cache policy package:architecture ...

# Authoritatively compare differing Debian versions
dpkg --compare-versions candidate gt installed
```

Policy queries are bounded by package count and argument bytes. The backend also reads `/run/reboot-required`, bounded retained APT history logs, and participating index mtimes. It never invokes interactive `apt`, `apt-get update`, package download, simulation, or installation commands.
