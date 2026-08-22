# Zabbix DNF Plugin

A loadable `zabbix-agent2` plugin that collects:

* Enabled DNF repositories
* Available package updates
* Security, bugfix, enhancement, and uncategorized update counts
* Update counts per repository
* Pending reboot status
* Most recent package update time and result

The plugin returns the collected data as a single JSON payload for use with dependent items and discovery rules.

![](https://i.imgur.com/aZmet8Y.png)

![](https://i.imgur.com/a5r5mLX.png)

![](https://i.imgur.com/tjaKnW2.png)

![](https://i.imgur.com/xZ5RQUk.png)

## Install the plugin

The plugin works on `zabbix-agent2` 7.0.5 or newer. Due to Go API changes 7.2 and 7.4 are not supported.

### Automated installation

Run this command:

```bash
curl -fLO https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/latest/download/install.sh && sudo sh install.sh
```

The installer downloads and verifies the plugin, installs the binary and configuration, verifies DNF access as the `zabbix` user, restores SELinux contexts, restarts `zabbix-agent2` and tests the plugin.

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

# Confirm that the zabbix user can query DNF
sudo -u zabbix dnf -q repolist
sudo -u zabbix dnf -q repoquery --upgrades

# Restart the agent and check that it started correctly
sudo systemctl restart zabbix-agent2
systemctl status zabbix-agent2
```

### Troubleshooting

```bash
# Test if the raw dnf.get item works as the zabbix user
sudo -u zabbix zabbix_agent2 -c /etc/zabbix/zabbix_agent2.conf -t dnf.get

# Run the plugin directly without the zabbix-agent2 socket protocol and print the collected JSON:
sudo /usr/sbin/zabbix-agent2-plugin/zabbix-dnf-plugin --test

# Check for SELinux policy denials
sudo ausearch -m AVC -ts recent
```

## Import the Zabbix template

Download the template from the GitHub release.

In Zabbix, go to **Data collection > Templates > Import** and import the downloaded `template-dnf-by-zabbix-agent2.yaml` file. Then link **DNF by Zabbix agent 2** to each host running the plugin.

The template creates the required monitoring items, repository discovery, and alerts automatically.

### Template details

**Macros**

|Name|Description|Default|
|----|-----------|-------|
|{$DNF.COLLECTION.DURATION.MAX}|Maximum acceptable average collection duration, in seconds.|`20`|
|{$DNF.COLLECTION.DURATION.WINDOW}|Evaluation window for the average collection duration.|`30m`|
|{$DNF.NODATA.TIME}|Time without a successful collection before an availability problem is raised.|`30m`|
|{$DNF.SECURITY.MIN}|Minimum number of security updates that raises a problem.|`1`|
|{$DNF.UPDATE.INTERVAL}|Interval between complete DNF collections.|`15m`|

**Items**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Get update data|Collects the complete package, repository, advisory, reboot, and update-history payload. The raw JSON is not retained because dependent items extract the monitored values.|Zabbix agent|dnf.get|
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

**Triggers**

|Name|Description|Expression|Severity|Dependencies and additional info|
|----|-----------|----------|--------|--------------------------------|
|DNF: Collection is unavailable|DNF update data is stale or unavailable until collection succeeds.|`last(/DNF by Zabbix agent 2/dnf.collection.complete)=0 or nodata(/DNF by Zabbix agent 2/dnf.collection.complete,{$DNF.NODATA.TIME})=1`|High||
|DNF: Collection is slow|The average collection duration is approaching the hard plugin and item timeout. Check repository availability and DNF performance.|`avg(/DNF by Zabbix agent 2/dnf.collection.duration,{$DNF.COLLECTION.DURATION.WINDOW})>{$DNF.COLLECTION.DURATION.MAX}`|Warning||
|DNF: Reboot is required|A reboot is required to complete package updates.|`last(/DNF by Zabbix agent 2/dnf.reboot.pending)=1`|Warning||
|DNF: Security updates are available|One or more security updates are available.|`last(/DNF by Zabbix agent 2/dnf.updates.security)>={$DNF.SECURITY.MIN}`|High||
|DNF: Last package update failed|The most recent package update transaction did not complete successfully.|`last(/DNF by Zabbix agent 2/dnf.last_update.result)=2`|Warning||

**LLD rule DNF: Repository discovery**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Repository discovery|Discovers enabled DNF repositories. Items for repositories that disappear are disabled immediately and retained for 30 days before deletion.|Dependent item|dnf.repository|

**Item prototypes for DNF: Repository discovery**

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|DNF: Repository [{#REPO_NAME}]: Available update count|Number of available package updates from repository {#REPO_NAME} ({#REPO_ID}).|Dependent item|dnf.repository.updates["{#REPO_ID}"]|
|DNF: Repository [{#REPO_NAME}]: Pending package details|Comma-separated NEVRA identifiers for packages with available updates from repository {#REPO_NAME} ({#REPO_ID}). The value is blank when there are no pending packages.|Dependent item|dnf.repository.update.details["{#REPO_ID}"]|

## Compatibility

All listed distributions are supported on x86_64 and exercised in CI:

* RHEL 8, 9, and 10.
* Fedora 43 and 44.
* Rocky Linux 9 and 10.
* AlmaLinux 9 and 10.
* CentOS Stream 9 and 10.

Due to recent changes to `zabbix-agent2` support is limited:
* `zabbix-agent2` 7.0.5 or newer in the 7.0 branch is supported.
* `zabbix-agent2` 7.2 and 7.4 branches are not supported.

Reboot status is determined from reboot-sensitive RPM install times and installed kernel packages compared with the running kernel. The plugin supports DNF4 and DNF5 without depending on an optional DNF reboot-detection plugin.

## Development

The `.dev/docker-compose.yaml` file spins up an entire Zabbix environment with agents for all supported distributions.

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

Each agent image runs `install.sh` during its build, including checksum, DNF, configuration, and verifies the `dnf.get` item.

```bash
docker compose -f .dev/docker-compose.yaml up --build
```

The `zbx70_bootstrap` service waits for the Zabbix API, imports or updates both DNF templates, and creates the `DNF plugin lab` host group. It provisions the eleven distribution hosts with passive agent interfaces and adds active-only UBI 9 and Fedora 44 hosts to exercise DNF4 and DNF5 with the active template. The bootstrap queues an initial collection for each passive host; active collections are scheduled and submitted by the agents.

## Build from source

Building the plugin requires Go 1.27.0 or newer.

```bash
CGO_ENABLED=0 go build -o zabbix-dnf-plugin ./cmd/agent
```
