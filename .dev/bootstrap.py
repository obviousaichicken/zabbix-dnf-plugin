#!/usr/bin/env python3

import json
import os
import sys
import time
import urllib.error
import urllib.request


API_URL = os.getenv(
    "ZBX_API_URL",
    "http://zbx70_web:8080/api_jsonrpc.php",
)
API_USER = os.getenv("ZBX_API_USER", "Admin")
API_PASSWORD = os.getenv("ZBX_API_PASSWORD", "zabbix")
TEMPLATE_PATH = os.getenv(
    "ZBX_TEMPLATE_PATH",
    "/bootstrap/template-dnf-by-zabbix-agent2.yaml",
)
PASSIVE_TEMPLATE_NAME = "DNF by Zabbix agent 2"
ACTIVE_TEMPLATE_NAME = "DNF by Zabbix agent 2 active"
HOST_GROUP_NAME = "DNF plugin lab"
WAIT_TIMEOUT = int(os.getenv("ZBX_BOOTSTRAP_TIMEOUT", "180"))
TEMPLATE_ONLY = os.getenv("ZBX_TEMPLATE_ONLY", "0") == "1"

PASSIVE_HOSTS = (
    ("zbx70-ubi8-agent", "UBI 8 / DNF plugin", "zbx70_ubi8_agent"),
    ("zbx70-ubi9-agent", "UBI 9 / DNF plugin", "zbx70_ubi9_agent"),
    ("zbx70-ubi10-agent", "UBI 10 / DNF plugin", "zbx70_ubi10_agent"),
    ("zbx70-fedora43-agent", "Fedora 43 / DNF plugin", "zbx70_fedora43_agent"),
    ("zbx70-fedora44-agent", "Fedora 44 / DNF plugin", "zbx70_fedora44_agent"),
    ("zbx70-rocky9-agent", "Rocky Linux 9 / DNF plugin", "zbx70_rocky9_agent"),
    ("zbx70-rocky10-agent", "Rocky Linux 10 / DNF plugin", "zbx70_rocky10_agent"),
    ("zbx70-alma9-agent", "AlmaLinux 9 / DNF plugin", "zbx70_alma9_agent"),
    ("zbx70-alma10-agent", "AlmaLinux 10 / DNF plugin", "zbx70_alma10_agent"),
    ("zbx70-centos9-agent", "CentOS Stream 9 / DNF plugin", "zbx70_centos9_agent"),
    ("zbx70-centos10-agent", "CentOS Stream 10 / DNF plugin", "zbx70_centos10_agent"),
)

ACTIVE_HOSTS = (
    ("zbx70-ubi9-agent-active", "UBI 9 / DNF plugin (active)", None),
    ("zbx70-fedora44-agent-active", "Fedora 44 / DNF plugin (active)", None),
)


class ZabbixAPI:
    def __init__(self, url):
        self.url = url
        self.auth = None
        self.request_id = 0

    def call(self, method, params, authenticated=True):
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id,
        }
        if authenticated:
            payload["auth"] = self.auth

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json-rpc"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)

        if "error" in result:
            error = result["error"]
            detail = error.get("data") or error.get("message") or str(error)
            raise RuntimeError(f"{method}: {detail}")

        return result["result"]


def wait_for_api(api):
    deadline = time.monotonic() + WAIT_TIMEOUT
    while time.monotonic() < deadline:
        try:
            version = api.call("apiinfo.version", {}, authenticated=False)
            print(f"Zabbix API {version} is ready")
            return
        except (OSError, RuntimeError, urllib.error.URLError):
            time.sleep(2)

    raise TimeoutError(
        f"Zabbix API did not become ready within {WAIT_TIMEOUT} seconds",
    )


def import_template(api):
    with open(TEMPLATE_PATH, encoding="utf-8") as template_file:
        source = template_file.read()

    api.call(
        "configuration.import",
        {
            "format": "yaml",
            "rules": {
                "template_groups": {
                    "createMissing": True,
                    "updateExisting": True,
                },
                "templates": {
                    "createMissing": True,
                    "updateExisting": True,
                },
                "items": {
                    "createMissing": True,
                    "updateExisting": True,
                    "deleteMissing": False,
                },
                "discoveryRules": {
                    "createMissing": True,
                    "updateExisting": True,
                    "deleteMissing": False,
                },
                "triggers": {
                    "createMissing": True,
                    "updateExisting": True,
                    "deleteMissing": False,
                },
                "valueMaps": {
                    "createMissing": True,
                    "updateExisting": True,
                    "deleteMissing": False,
                },
            },
            "source": source,
        },
    )
    print(
        "Imported templates: "
        f"{PASSIVE_TEMPLATE_NAME}, {ACTIVE_TEMPLATE_NAME}",
    )


def get_or_create_host_group(api):
    groups = api.call(
        "hostgroup.get",
        {"output": ["groupid"], "filter": {"name": [HOST_GROUP_NAME]}},
    )
    if groups:
        return groups[0]["groupid"]

    result = api.call("hostgroup.create", {"name": HOST_GROUP_NAME})
    return result["groupids"][0]


def get_template_id(api, template_name):
    templates = api.call(
        "template.get",
        {"output": ["templateid"], "filter": {"host": [template_name]}},
    )
    if not templates:
        raise RuntimeError(f"imported template not found: {template_name}")

    return templates[0]["templateid"]


def related_ids(api, method, host_id, id_field):
    objects = api.call(method, {"output": [id_field], "hostids": [host_id]})
    return {item[id_field] for item in objects}


def ensure_agent_interface(api, host_id, interfaces, dns_name):
    agent_interfaces = [
        interface
        for interface in interfaces
        if interface["type"] == "1" and interface["main"] == "1"
    ]
    interface = {
        "type": 1,
        "main": 1,
        "useip": 0,
        "ip": "",
        "dns": dns_name,
        "port": "10050",
    }

    if agent_interfaces:
        interface["interfaceid"] = agent_interfaces[0]["interfaceid"]
        api.call("hostinterface.update", interface)
        return

    interface["hostid"] = host_id
    api.call("hostinterface.create", interface)


def ensure_host(api, host_name, visible_name, dns_name, group_id, template_id):
    hosts = api.call(
        "host.get",
        {
            "output": ["hostid"],
            "filter": {"host": [host_name]},
            "selectInterfaces": [
                "interfaceid",
                "type",
                "main",
                "useip",
                "ip",
                "dns",
                "port",
            ],
        },
    )

    if not hosts:
        host = {
            "host": host_name,
            "name": visible_name,
            "groups": [{"groupid": group_id}],
            "templates": [{"templateid": template_id}],
        }
        if dns_name is not None:
            host["interfaces"] = [
                {
                    "type": 1,
                    "main": 1,
                    "useip": 0,
                    "ip": "",
                    "dns": dns_name,
                    "port": "10050",
                },
            ]

        result = api.call("host.create", host)
        host_id = result["hostids"][0]
        print(f"Created host: {host_name} ({host_id})")
        return host_id

    host = hosts[0]
    host_id = host["hostid"]
    group_ids = related_ids(api, "hostgroup.get", host_id, "groupid")
    template_ids = related_ids(api, "template.get", host_id, "templateid")
    group_ids.add(group_id)
    template_ids.add(template_id)

    api.call(
        "host.update",
        {
            "hostid": host_id,
            "name": visible_name,
            "groups": [{"groupid": value} for value in sorted(group_ids)],
            "templates": [
                {"templateid": value} for value in sorted(template_ids)
            ],
        },
    )
    if dns_name is not None:
        ensure_agent_interface(api, host_id, host["interfaces"], dns_name)
    print(f"Updated host: {host_name} ({host_id})")

    return host_id


def execute_master_items(api, host_ids):
    items = api.call(
        "item.get",
        {
            "output": ["itemid"],
            "hostids": host_ids,
            "filter": {"key_": ["dnf.get"]},
        },
    )
    if len(items) != len(host_ids):
        raise RuntimeError(
            f"found {len(items)} dnf.get items for {len(host_ids)} hosts",
        )

    api.call(
        "task.create",
        [
            {"type": 6, "request": {"itemid": item["itemid"]}}
            for item in items
        ],
    )
    print(f"Queued initial collection for {len(items)} hosts")


def main():
    api = ZabbixAPI(API_URL)
    wait_for_api(api)
    api.auth = api.call(
        "user.login",
        {"username": API_USER, "password": API_PASSWORD},
        authenticated=False,
    )

    import_template(api)
    passive_template_id = get_template_id(api, PASSIVE_TEMPLATE_NAME)
    active_template_id = get_template_id(api, ACTIVE_TEMPLATE_NAME)
    if TEMPLATE_ONLY:
        print(
            "Validated templates: "
            f"{PASSIVE_TEMPLATE_NAME} ({passive_template_id}), "
            f"{ACTIVE_TEMPLATE_NAME} ({active_template_id})",
        )
        return

    group_id = get_or_create_host_group(api)
    passive_host_ids = [
        ensure_host(api, *host, group_id, passive_template_id)
        for host in PASSIVE_HOSTS
    ]
    for host in ACTIVE_HOSTS:
        ensure_host(api, *host, group_id, active_template_id)

    execute_master_items(api, passive_host_ids)

    print("Zabbix lab bootstrap completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Zabbix lab bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
