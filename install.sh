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

	case "$1.$2" in
	7.0 | 7.2 | 7.4) ;;
	*)
		fail "unsupported Zabbix Agent 2 version $agent_version; require 7.0, 7.2, or 7.4"
		;;
	esac
}

check_operating_system() {
	[ -r /etc/os-release ] || fail "cannot read /etc/os-release"

	# shellcheck disable=SC1091 # The operating system provides this file.
	. /etc/os-release
	os_id="${ID:-}"
	os_version="${VERSION_ID:-}"

	case "$os_id" in
	debian)
		case "$os_version" in
		12 | 13)
			package_backend=apt
			return
			;;
		*) fail "unsupported Debian version ${os_version:-unknown}; require Debian 12 or 13" ;;
		esac
		;;
	ubuntu)
		case "$os_version" in
		22.04 | 24.04 | 26.04)
			package_backend=apt
			return
			;;
		*) fail "unsupported Ubuntu version ${os_version:-unknown}; require Ubuntu 22.04, 24.04, or 26.04" ;;
		esac
		;;
	esac

	# Preserve the existing DNF-family version gate for all other IDs.
	os_major="${os_version%%.*}"

	case "$os_major" in
	'' | *[!0-9]*)
		fail "cannot parse operating system version: ${os_version:-unknown}"
		;;
	esac

	if [ "$os_major" -lt 8 ]; then
		fail "unsupported operating system version $os_version; require a DNF-based version 8 or newer"
	fi

	package_backend=dnf
}

check_dnf_access() {
	printf '%s\n' 'Checking DNF access...'
	dnf_path="$(command -v dnf)"
	run_as_zabbix "$dnf_path" --assumeyes -q repolist </dev/null >/dev/null ||
		fail "the zabbix user cannot list DNF repositories"
	run_as_zabbix "$dnf_path" --assumeyes -q repoquery --upgrades </dev/null >/dev/null ||
		fail "the zabbix user cannot query DNF updates"
}

check_apt_access() {
	printf '%s\n' 'Checking APT access...'
	apt_get_path="$(command -v apt-get)"
	apt_cache_path="$(command -v apt-cache)"
	dpkg_query_path="$(command -v dpkg-query)"
	dpkg_path="$(command -v dpkg)"

	apt_index_output="$(run_as_zabbix "$apt_get_path" indextargets)" ||
		fail "the zabbix user cannot inspect APT package indexes"
	case "$apt_index_output" in
	*'Identifier: Packages'*) ;;
	*)
		fail "APT package indexes are not populated; run apt-get update as root and retry"
		;;
	esac

	run_as_zabbix "$dpkg_query_path" --show \
		'--showformat=${binary:Package}|${Architecture}|${Version}|${db:Status-Status}\n' \
		>/dev/null || fail "the zabbix user cannot query installed packages"

	policy_package="$(
		run_as_zabbix "$dpkg_query_path" --show \
			'--showformat=${Package}:${Architecture}\n' dpkg
	)" || fail "the zabbix user cannot resolve an installed package for APT policy preflight"
	[ -n "$policy_package" ] || fail "APT policy preflight found no installed dpkg package"
	run_as_zabbix "$apt_cache_path" policy "$policy_package" >/dev/null ||
		fail "the zabbix user cannot query APT package policy"
	run_as_zabbix "$dpkg_path" --compare-versions 1 eq 1 ||
		fail "the zabbix user cannot compare Debian package versions"
}

test_agent_item() {
	item_key=$1
	expected_backend=$2

	printf 'Testing %s as the zabbix user...\n' "$item_key"
	test_output="$(
		run_as_zabbix \
			zabbix_agent2 -c "$agent_config" -t "$item_key"
	)"
	printf '%s\n' "$test_output"

	case "$test_output" in
	*"[s|"*'"collection":{"complete":true'*) ;;
	*) fail "$item_key did not return a complete collection" ;;
	esac
	if [ -n "$expected_backend" ]; then
		case "$test_output" in
		*"\"backend\":\"${expected_backend}\""*) ;;
		*) fail "$item_key did not report the $expected_backend backend" ;;
		esac
	fi
}

if [ "$(id -u)" -ne 0 ]; then
	fail "run this installer as root"
fi

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
	fail "only Linux on x86_64 is supported"
fi

package_backend=
check_operating_system

for command_name in curl env getent sha256sum install mktemp runuser zabbix_agent2; do
	command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
done

case "$package_backend" in
dnf)
	for command_name in dnf rpm; do
		command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
	done
	;;
apt)
	for command_name in apt-get apt-cache dpkg-query dpkg; do
		command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
	done
	;;
*) fail "internal error: no package backend selected" ;;
esac

zabbix_account="$(getent passwd zabbix)" || fail "required user not found: zabbix"
zabbix_home="${zabbix_account%:*}"
zabbix_home="${zabbix_home##*:}"

case "$zabbix_home" in
'' | /)
	fail "invalid home directory for zabbix user: ${zabbix_home:-empty}"
	;;
/*) ;;
*) fail "zabbix user home is not an absolute path: $zabbix_home" ;;
esac

if [ ! -e "$zabbix_home" ]; then
	install -d -m 0755 -o zabbix -g zabbix "$zabbix_home"
elif [ ! -d "$zabbix_home" ]; then
	fail "zabbix user home is not a directory: $zabbix_home"
fi

if command -v restorecon >/dev/null 2>&1; then
	restorecon -R "$zabbix_home"
fi

printf '%s\n' 'Checking Zabbix Agent 2 version...'
check_agent_version

tmp_dir="$(mktemp -d)"
install -d -m 0755 "$tmp_dir"

cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup 0

run_as_zabbix() {
	runuser -u zabbix -- env HOME="$zabbix_home" "$@"
}

case "$package_backend" in
dnf) check_dnf_access ;;
apt) check_apt_access ;;
esac

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

case "$package_backend" in
dnf)
	test_agent_item dnf.get ""
	test_agent_item packages.get dnf
	;;
apt) test_agent_item packages.get apt ;;
esac

printf '%s\n' 'Installation completed successfully.'
