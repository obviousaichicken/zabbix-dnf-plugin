#!/bin/sh

set -eu

release_url="${RELEASE_URL:-https://github.com/obviousaichicken/zabbix-dnf-plugin/releases/latest/download}"
plugin_dir="/usr/sbin/zabbix-agent2-plugin"
plugin_path="${plugin_dir}/zabbix-dnf-plugin"
config_dir="/etc/zabbix/zabbix_agent2.d/plugins.d"
config_path="${config_dir}/dnf.conf"
agent_config="/etc/zabbix/zabbix_agent2.conf"

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

check_agent_version() {
	agent_version_output="$(zabbix_agent2 --version 2>&1)" ||
		fail "cannot read Zabbix Agent 2 version"

	set -- $agent_version_output
	agent_version="${3:-}"
	previous_ifs=$IFS
	IFS=.
	set -- $agent_version
	IFS=$previous_ifs

	if [ "$#" -ne 3 ]; then
		fail "cannot parse Zabbix Agent 2 version: ${agent_version:-unknown}"
	fi

	for component in "$@"; do
		case "$component" in
		'' | *[!0-9]*)
			fail "cannot parse Zabbix Agent 2 version: $agent_version"
			;;
		esac
	done

	if [ "$1" -ne 7 ] || [ "$2" -ne 0 ] || [ "$3" -lt 5 ]; then
		fail "unsupported Zabbix Agent 2 version $agent_version; require 7.0.5 or newer in the 7.0 branch"
	fi
}

check_operating_system() {
	[ -r /etc/os-release ] || fail "cannot read /etc/os-release"

	# shellcheck disable=SC1091 # The operating system provides this file.
	. /etc/os-release
	os_version="${VERSION_ID:-}"
	os_major="${os_version%%.*}"

	case "$os_major" in
	'' | *[!0-9]*)
		fail "cannot parse operating system version: ${os_version:-unknown}"
		;;
	esac

	if [ "$os_major" -lt 8 ]; then
		fail "unsupported operating system version $os_version; require a DNF-based version 8 or newer"
	fi
}

if [ "$(id -u)" -ne 0 ]; then
	fail "run this installer as root"
fi

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
	fail "only Linux on x86_64 is supported"
fi

check_operating_system

for command_name in curl dnf env sha256sum install mktemp rpm runuser zabbix_agent2; do
	command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
done

id zabbix >/dev/null 2>&1 || fail "required user not found: zabbix"

printf '%s\n' 'Checking Zabbix Agent 2 version...'
check_agent_version

tmp_dir="$(mktemp -d)"
install -d -m 0755 "$tmp_dir"
zabbix_home="${tmp_dir}/zabbix-home"
install -d -m 0700 -o zabbix "$zabbix_home"

cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup 0

run_as_zabbix() {
	runuser -u zabbix -- env HOME="$zabbix_home" "$@"
}

printf '%s\n' 'Checking DNF access...'
dnf_path="$(command -v dnf)"
run_as_zabbix "$dnf_path" -q repolist >/dev/null ||
	fail "the zabbix user cannot list DNF repositories"
run_as_zabbix "$dnf_path" -q repoquery --upgrades >/dev/null ||
	fail "the zabbix user cannot query DNF updates"

printf '%s\n' 'Downloading release files...'
for file_name in zabbix-dnf-plugin zabbix-dnf-plugin.sha256 dnf.conf; do
	curl -fL --retry 3 \
		-o "${tmp_dir}/${file_name}" \
		"${release_url}/${file_name}"
done

printf '%s\n' 'Verifying checksum...'
(
	cd "$tmp_dir"
	sha256sum --check zabbix-dnf-plugin.sha256
)

printf '%s\n' 'Installing plugin and configuration...'
install -d -m 0755 "$plugin_dir" "$config_dir"
install -m 0755 "${tmp_dir}/zabbix-dnf-plugin" "$plugin_path"
install -m 0644 "${tmp_dir}/dnf.conf" "$config_path"

if command -v restorecon >/dev/null 2>&1; then
	restorecon -R "$plugin_dir"
	restorecon "$config_path"
fi

printf '%s\n' 'Validating Zabbix Agent 2 configuration...'
zabbix_agent2 -T -c "$agent_config"

if [ "${SKIP_SERVICE_RESTART:-0}" = "1" ]; then
	printf '%s\n' 'Skipping service restart for container image build.'
else
	command -v systemctl >/dev/null 2>&1 || fail "required command not found: systemctl"
	printf '%s\n' 'Restarting Zabbix Agent 2...'
	systemctl restart zabbix-agent2
	systemctl is-active --quiet zabbix-agent2 || fail "zabbix-agent2 did not start"
fi

printf '%s\n' 'Testing dnf.get as the zabbix user...'
test_output="$(
	run_as_zabbix \
		zabbix_agent2 -c "$agent_config" -t dnf.get
)"
printf '%s\n' "$test_output"

case "$test_output" in
	*"[s|"*'"collection":{"complete":true'*) ;;
	*) fail "dnf.get did not return a complete collection" ;;
esac

printf '%s\n' 'Installation completed successfully.'
