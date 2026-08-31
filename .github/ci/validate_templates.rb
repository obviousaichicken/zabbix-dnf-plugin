#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "yaml"

ROOT = File.expand_path("../..", __dir__)
TEMPLATE_FILE = File.join(ROOT, "template-dnf-by-zabbix-agent2.yaml")
UUID_PATTERN = /\A[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\z/
NODE_DISCOVERY_HARNESS = <<~'JAVASCRIPT'
  const fs = require('fs');
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  let source = input.source;

  for (const [macro, value] of Object.entries(input.macros)) {
    source = source.split(macro).join(value);
  }

  try {
    const output = Function('value', source)(JSON.stringify(input.payload));
    const records = JSON.parse(output);
    process.stdout.write(JSON.stringify({ok: true, records}));
  } catch (error) {
    process.stdout.write(JSON.stringify({ok: false, error: String(error)}));
  }
JAVASCRIPT

def fail_contract(message)
  warn "template contract failed: #{message}"
  exit 1
end

def walk(value, &block)
  yield value
  case value
  when Hash
    value.each_value { |child| walk(child, &block) }
  when Array
    value.each { |child| walk(child, &block) }
  end
end

def collect_uuids(value)
  uuids = []
  walk(value) do |node|
    uuids << node["uuid"] if node.is_a?(Hash) && node.key?("uuid")
  end
  uuids
end

def run_advisory_discovery(source, payload, macros)
  request = JSON.generate({source: source, payload: payload, macros: macros})
  stdout, stderr, status = Open3.capture3(
    "node", "-e", NODE_DISCOVERY_HARNESS, stdin_data: request
  )
  unless status.success?
    fail_contract("cannot execute advisory discovery JavaScript: #{stderr.strip}")
  end

  JSON.parse(stdout)
rescue Errno::ENOENT => error
  fail_contract("Node.js is required for advisory discovery fixtures: #{error.message}")
rescue JSON::ParserError => error
  fail_contract("advisory discovery fixture returned invalid JSON: #{error.message}")
end

def normalize_pair(value, active_name, passive_name)
  case value
  when Hash
    value.each_with_object({}) do |(key, child), normalized|
      next if key == "uuid"

      normalized[key] = normalize_pair(child, active_name, passive_name)
    end
  when Array
    value.map { |child| normalize_pair(child, active_name, passive_name) }
  when String
    return "ZABBIX_AGENT" if ["ZABBIX_ACTIVE", "ZABBIX_PASSIVE"].include?(value)

    value.gsub(active_name, passive_name)
  else
    value
  end
end

def validate_master_references(template)
  template_name = template.fetch("template")
  items = template.fetch("items")
  item_keys = items.map { |item| item.fetch("key") }
  fail_contract("#{template_name} has duplicate item keys") unless item_keys.uniq == item_keys

  check_reference = lambda do |object|
    master = object["master_item"]
    if object["type"] == "DEPENDENT" && master.nil?
      fail_contract("#{template_name} dependent #{object['key']} has no master item")
    end
    return if master.nil?

    key = master.fetch("key")
    unless item_keys.include?(key)
      fail_contract("#{template_name} #{object['key']} references missing master #{key}")
    end
  end

  items.each(&check_reference)
  template.fetch("discovery_rules", []).each do |rule|
    check_reference.call(rule)
    rule.fetch("item_prototypes", []).each(&check_reference)
  end
end

export = begin
  YAML.safe_load(File.read(TEMPLATE_FILE), aliases: false).fetch("zabbix_export")
rescue Errno::ENOENT, Psych::SyntaxError, KeyError => error
  fail_contract("cannot load #{TEMPLATE_FILE}: #{error.message}")
end

fail_contract("combined export version is not 7.0") unless export["version"] == "7.0"

uuids = collect_uuids(export)
invalid = uuids.reject { |uuid| uuid.is_a?(String) && UUID_PATTERN.match?(uuid) }
fail_contract("combined export has invalid UUIDs: #{invalid.inspect}") unless invalid.empty?

duplicates = uuids.tally.select { |_uuid, count| count > 1 }.keys
unless duplicates.empty?
  fail_contract("combined export has duplicate UUIDs: #{duplicates.join(', ')}")
end

all_templates = export.fetch("templates")
fail_contract("combined export must contain four templates") unless all_templates.length == 4

templates_by_family = %w[DNF APT].to_h do |family|
  passive_name = "#{family} by Zabbix agent 2"
  active_name = "#{passive_name} active"
  templates = all_templates.select do |template|
    [passive_name, active_name].include?(template["template"])
  end
  passive = templates.find { |template| template["template"] == passive_name }
  active = templates.find { |template| template["template"] == active_name }
  fail_contract("#{family} passive/active template pair is incomplete") if passive.nil? || active.nil?
  fail_contract("#{family} family contains unexpected templates") unless templates.length == 2

  normalized_passive = normalize_pair(passive, active_name, passive_name)
  normalized_active = normalize_pair(active, active_name, passive_name)
  unless normalized_passive == normalized_active
    fail_contract("#{family} passive and active templates are not structurally equivalent")
  end

  templates.each { |template| validate_master_references(template) }
  [family, templates]
end

expected_names = %w[DNF APT].flat_map do |family|
  passive_name = "#{family} by Zabbix agent 2"
  [passive_name, "#{passive_name} active"]
end
actual_names = all_templates.map { |template| template.fetch("template") }
unless actual_names.sort == expected_names.sort
  fail_contract("combined export contains unexpected templates: #{actual_names.inspect}")
end

dnf_owned = collect_uuids(templates_by_family.fetch("DNF"))
apt_owned = collect_uuids(templates_by_family.fetch("APT"))
overlap = dnf_owned & apt_owned
fail_contract("APT-owned UUIDs are not fresh: #{overlap.join(', ')}") unless overlap.empty?

dnf_templates = templates_by_family.fetch("DNF")
expected_dnf_keys = %w[
  dnf.get
  dnf.advisories.get
  dnf.advisory.discovery.data
  dnf.collection.complete
  dnf.collection.duration
  dnf.classification.complete
  dnf.updates
  dnf.repositories
  dnf.updates.pending
  dnf.reboot.pending
  dnf.updates.security
  dnf.updates.bugfix
  dnf.updates.enhancement
  dnf.updates.other
  dnf.last_update.result
  dnf.last_update.timestamp
  dnf.advisory.collection.complete
  dnf.advisory.collection.duration
  dnf.advisory.details.complete
  dnf.advisory.cves.complete
  dnf.advisory.issue_dates.complete
  dnf.advisory.total
  dnf.advisory.cves
  dnf.advisory.critical
  dnf.advisory.important
  dnf.advisory.moderate
  dnf.advisory.low
  dnf.advisory.unknown
  dnf.advisory.packages.critical
  dnf.advisory.packages.important
  dnf.advisory.packages.moderate
  dnf.advisory.packages.low
  dnf.advisory.packages.unknown
  dnf.advisory.oldest.timestamp
  dnf.advisory.oldest.age
  dnf.advisory.oldest.basis
].sort.freeze
expected_dnf_macros = %w[
  {$DNF.ADVISORY.LLD.CRITICAL}
  {$DNF.ADVISORY.LLD.IMPORTANT}
  {$DNF.ADVISORY.LLD.LOW}
  {$DNF.ADVISORY.LLD.MODERATE}
  {$DNF.ADVISORY.LLD.UNKNOWN}
  {$DNF.ADVISORY.NODATA.TIME}
  {$DNF.ADVISORY.UPDATE.INTERVAL}
  {$DNF.COLLECTION.DURATION.MAX}
  {$DNF.COLLECTION.DURATION.WINDOW}
  {$DNF.NODATA.TIME}
  {$DNF.SECURITY.ADVISORY.MAX.AGE}
  {$DNF.SECURITY.CRITICAL.MIN}
  {$DNF.SECURITY.IMPORTANT.MIN}
  {$DNF.SECURITY.MIN}
  {$DNF.SECURITY.UNKNOWN.MAX}
  {$DNF.UPDATE.INTERVAL}
].sort.freeze
advisory_lld_macros = %w[
  {$DNF.ADVISORY.LLD.CRITICAL}
  {$DNF.ADVISORY.LLD.IMPORTANT}
  {$DNF.ADVISORY.LLD.MODERATE}
  {$DNF.ADVISORY.LLD.LOW}
  {$DNF.ADVISORY.LLD.UNKNOWN}
].freeze
advisory_jsonpaths = {
  "dnf.advisory.collection.complete" => "$.collection.complete",
  "dnf.advisory.collection.duration" => "$.collection.duration_ms",
  "dnf.advisory.details.complete" => "$.metadata.details_complete",
  "dnf.advisory.cves.complete" => "$.metadata.cves_complete",
  "dnf.advisory.issue_dates.complete" => "$.metadata.issue_dates_complete",
  "dnf.advisory.total" => "$.summary.advisories",
  "dnf.advisory.cves" => "$.summary.unique_cves",
  "dnf.advisory.critical" => "$.summary.advisories_by_severity.critical",
  "dnf.advisory.important" => "$.summary.advisories_by_severity.important",
  "dnf.advisory.moderate" => "$.summary.advisories_by_severity.moderate",
  "dnf.advisory.low" => "$.summary.advisories_by_severity.low",
  "dnf.advisory.unknown" => "$.summary.advisories_by_severity.unknown",
  "dnf.advisory.packages.critical" => "$.summary.package_updates_by_severity.critical",
  "dnf.advisory.packages.important" => "$.summary.package_updates_by_severity.important",
  "dnf.advisory.packages.moderate" => "$.summary.package_updates_by_severity.moderate",
  "dnf.advisory.packages.low" => "$.summary.package_updates_by_severity.low",
  "dnf.advisory.packages.unknown" => "$.summary.package_updates_by_severity.unknown",
  "dnf.advisory.oldest.basis" => "$.summary.oldest_vendor_timestamp_basis"
}.freeze
advisory_discovery_scripts = []

dnf_templates.each do |template|
  template_name = template.fetch("template")
  items = template.fetch("items")
  items_by_key = items.to_h { |item| [item.fetch("key"), item] }
  keys = items_by_key.keys.sort
  fail_contract("#{template_name} DNF item set is incomplete") unless keys == expected_dnf_keys

  macro_values = template.fetch("macros").to_h do |macro|
    [macro.fetch("macro"), macro.fetch("value")]
  end
  fail_contract("#{template_name} DNF macro set is incomplete") unless macro_values.keys.sort == expected_dnf_macros
  advisory_lld_macros.each do |macro|
    unless macro_values.fetch(macro) == "0"
      fail_contract("#{template_name} #{macro} must be disabled by default")
    end
  end

  master = items_by_key.fetch("dnf.advisories.get")
  expected_type = template_name.end_with?(" active") ? "ZABBIX_ACTIVE" : "ZABBIX_PASSIVE"
  unless master["type"] == expected_type &&
         master["delay"] == "{$DNF.ADVISORY.UPDATE.INTERVAL}" &&
         master["history"] == "0" && master["value_type"] == "TEXT" &&
         master["timeout"] == "30s"
    fail_contract("#{template_name} advisory master contract is invalid")
  end

  discovery_data = items_by_key.fetch("dnf.advisory.discovery.data")
  discovery_steps = discovery_data.fetch("preprocessing")
  unless discovery_data["type"] == "DEPENDENT" && discovery_data["history"] == "0" &&
         discovery_data["value_type"] == "TEXT" &&
         discovery_data.dig("master_item", "key") == "dnf.advisories.get" &&
         discovery_steps.length == 1 && discovery_steps.first["type"] == "JAVASCRIPT"
    fail_contract("#{template_name} advisory discovery projection contract is invalid")
  end
  discovery_javascript = discovery_steps.first.dig("parameters", 0)
  required_discovery_fragments = [
    "data.schema_version !== 1",
    "data.collection.complete !== true",
    "data.metadata.details_complete !== true",
    "data.metadata.cves_complete !== true",
    "data.metadata.issue_dates_complete !== true",
    "must be exactly 0 or 1",
    "id.length > 256",
    "id.charCodeAt(character).toString(16)",
    "return JSON.stringify(records)"
  ]
  unless required_discovery_fragments.all? { |fragment| discovery_javascript.include?(fragment) }
    fail_contract("#{template_name} advisory discovery projection is not fail-closed and key-safe")
  end
  advisory_discovery_scripts << discovery_javascript

  discovery = template.fetch("discovery_rules").find do |rule|
    rule["key"] == "dnf.advisory.discovery"
  end
  fail_contract("#{template_name} has no advisory discovery rule") if discovery.nil?
  unless discovery["type"] == "DEPENDENT" && discovery["lifetime_type"] == "DELETE_AFTER" &&
         discovery["lifetime"] == "30d" && discovery["enabled_lifetime_type"] == "DISABLE_AFTER" &&
         discovery["enabled_lifetime"] == "1d" &&
         discovery.dig("master_item", "key") == "dnf.advisory.discovery.data"
    fail_contract("#{template_name} advisory discovery lifecycle is invalid")
  end

  expected_prototype_keys = %w[
    dnf.advisory.presence[{#ADVISORY_SAFE_ID}]
    dnf.advisory.vendor.timestamp[{#ADVISORY_SAFE_ID}]
    dnf.advisory.packages.count[{#ADVISORY_SAFE_ID}]
    dnf.advisory.packages.list[{#ADVISORY_SAFE_ID}]
    dnf.advisory.cves.list[{#ADVISORY_SAFE_ID}]
  ].sort
  prototypes = discovery.fetch("item_prototypes")
  unless prototypes.map { |prototype| prototype.fetch("key") }.sort == expected_prototype_keys
    fail_contract("#{template_name} advisory item prototype set is invalid")
  end
  prototypes.each do |prototype|
    key = prototype.fetch("key")
    unless key.include?("{#ADVISORY_SAFE_ID}") && !key.include?("{#ADVISORY_ID}") &&
           prototype.fetch("name").include?("{#ADVISORY_ID}") &&
           prototype.dig("master_item", "key") == "dnf.advisory.discovery.data"
      fail_contract("#{template_name} prototype #{key} exposes an unsafe advisory key")
    end
    tags = prototype.fetch("tags", []).to_h { |tag| [tag.fetch("tag"), tag.fetch("value")] }
    unless tags["advisory"] == "{#ADVISORY_ID}" && tags["severity"] == "{#ADVISORY_SEVERITY}"
      fail_contract("#{template_name} prototype #{key} loses advisory identity tags")
    end
  end

  presence = prototypes.find { |prototype| prototype["key"].start_with?("dnf.advisory.presence[") }
  presence_step = presence.fetch("preprocessing").first
  unless presence_step["type"] == "JSONPATH" && presence_step["error_handler"] == "CUSTOM_VALUE" &&
         presence_step["error_handler_params"] == "0"
    fail_contract("#{template_name} advisory presence does not recover on disappearance")
  end

  expected_lld_paths = {
    "{#ADVISORY_ID}" => "$.id",
    "{#ADVISORY_SAFE_ID}" => "$.safe_id",
    "{#ADVISORY_SEVERITY}" => "$.severity",
    "{#ADVISORY_TITLE}" => "$.title"
  }
  actual_lld_paths = discovery.fetch("lld_macro_paths").to_h do |path|
    [path.fetch("lld_macro"), path.fetch("path")]
  end
  unless actual_lld_paths == expected_lld_paths
    fail_contract("#{template_name} advisory LLD projection paths are invalid")
  end

  trigger_prototypes = discovery.fetch("trigger_prototypes")
  unless trigger_prototypes.length == 1 &&
         trigger_prototypes.first.fetch("expression") ==
           "last(/#{template_name}/dnf.advisory.presence[{#ADVISORY_SAFE_ID}])=1"
    fail_contract("#{template_name} advisory trigger prototype is invalid")
  end
  expected_severity_overrides = {
    "critical" => "DISASTER",
    "important" => "HIGH",
    "moderate" => "WARNING",
    "low" => "INFO",
    "unknown" => "HIGH"
  }
  actual_severity_overrides = discovery.fetch("overrides").to_h do |override|
    condition = override.dig("filter", "conditions", 0)
    operation = override.fetch("operations").first
    unless condition&.fetch("macro", nil) == "{#ADVISORY_SEVERITY}" &&
           operation["operationobject"] == "TRIGGER_PROTOTYPE" &&
           operation["operator"] == "REGEXP" &&
           operation["value"] == "^DNF: Advisory \\["
      fail_contract("#{template_name} advisory severity override is invalid")
    end
    [condition.fetch("value").delete_prefix("^").delete_suffix("$"), operation.fetch("severity")]
  end
  unless actual_severity_overrides == expected_severity_overrides
    fail_contract("#{template_name} advisory trigger severities are mapped incorrectly")
  end

  items_by_key.each do |key, item|
    next unless key.start_with?("dnf.advisory.")

    unless item["type"] == "DEPENDENT" && item.dig("master_item", "key") == "dnf.advisories.get"
      fail_contract("#{template_name} #{key} is not linked to the advisory master")
    end
  end

  advisory_jsonpaths.each do |key, path|
    steps = items_by_key.fetch(key).fetch("preprocessing")
    jsonpath = steps.find { |step| step["type"] == "JSONPATH" }
    unless jsonpath&.dig("parameters", 0) == path
      fail_contract("#{template_name} #{key} has an invalid JSONPath")
    end
  end

  %w[
    dnf.advisory.collection.complete
    dnf.advisory.details.complete
    dnf.advisory.cves.complete
    dnf.advisory.issue_dates.complete
  ].each do |key|
    step_types = items_by_key.fetch(key).fetch("preprocessing").map { |step| step.fetch("type") }
    unless step_types == %w[JSONPATH BOOL_TO_DECIMAL]
      fail_contract("#{template_name} #{key} does not convert a boolean safely")
    end
  end

  timestamp_js = items_by_key.fetch("dnf.advisory.oldest.timestamp")
                         .fetch("preprocessing").first.dig("parameters", 0)
  age_js = items_by_key.fetch("dnf.advisory.oldest.age")
                   .fetch("preprocessing").first.dig("parameters", 0)
  unless timestamp_js.include?("oldest_vendor_timestamp") &&
         timestamp_js.include?("Date.parse") && timestamp_js.include?("return null")
    fail_contract("#{template_name} oldest timestamp preprocessing is not null-safe")
  end
  unless age_js.include?("oldest_vendor_age_seconds") &&
         age_js.include?("isFinite") && age_js.include?("return null")
    fail_contract("#{template_name} oldest age preprocessing is not bounded and null-safe")
  end

  triggers = items.flat_map { |item| item.fetch("triggers", []) }
  triggers_by_name = triggers.to_h { |trigger| [trigger.fetch("name"), trigger] }
  expected_triggers = {
    "DNF: Advisory collection is unavailable" => [
      "dnf.advisory.collection.complete", "{$DNF.ADVISORY.NODATA.TIME}"
    ],
    "DNF: Critical security advisories are applicable" => [
      "dnf.advisory.critical", "{$DNF.SECURITY.CRITICAL.MIN}"
    ],
    "DNF: Important security advisories are applicable" => [
      "dnf.advisory.critical", "dnf.advisory.important",
      "{$DNF.SECURITY.CRITICAL.MIN}", "{$DNF.SECURITY.IMPORTANT.MIN}"
    ],
    "DNF: Applicable security advisory is old" => [
      "dnf.advisory.oldest.age", "{$DNF.SECURITY.ADVISORY.MAX.AGE}"
    ],
    "DNF: Security advisory severity is unknown" => [
      "dnf.advisory.unknown", "dnf.advisory.packages.unknown",
      "{$DNF.SECURITY.UNKNOWN.MAX}"
    ],
    "DNF: Advisory metadata is incomplete" => [
      "dnf.advisory.details.complete", "dnf.advisory.cves.complete",
      "dnf.advisory.issue_dates.complete"
    ],
    "DNF: Security package updates lack advisory objects" => [
      "dnf.updates.security", "dnf.advisory.packages.critical",
      "dnf.advisory.packages.important", "dnf.advisory.packages.moderate",
      "dnf.advisory.packages.low", "dnf.advisory.packages.unknown"
    ]
  }.freeze
  expected_triggers.each do |name, fragments|
    expression = triggers_by_name[name]&.fetch("expression", nil)
    unless expression && fragments.all? { |fragment| expression.include?(fragment) }
      fail_contract("#{template_name} trigger #{name} has an invalid expression")
    end
  end

  expected_expressions = {
    "DNF: Advisory collection is unavailable" =>
      "last(/#{template_name}/dnf.advisory.collection.complete)=0 or " \
      "nodata(/#{template_name}/dnf.advisory.collection.complete,{$DNF.ADVISORY.NODATA.TIME})=1",
    "DNF: Critical security advisories are applicable" =>
      "last(/#{template_name}/dnf.advisory.critical)>={$DNF.SECURITY.CRITICAL.MIN}",
    "DNF: Important security advisories are applicable" =>
      "last(/#{template_name}/dnf.advisory.critical)<{$DNF.SECURITY.CRITICAL.MIN} and " \
      "last(/#{template_name}/dnf.advisory.important)>={$DNF.SECURITY.IMPORTANT.MIN}",
    "DNF: Applicable security advisory is old" =>
      "last(/#{template_name}/dnf.advisory.oldest.age)>{$DNF.SECURITY.ADVISORY.MAX.AGE}",
    "DNF: Security advisory severity is unknown" =>
      "last(/#{template_name}/dnf.advisory.unknown)>{$DNF.SECURITY.UNKNOWN.MAX} or " \
      "last(/#{template_name}/dnf.advisory.packages.unknown)>{$DNF.SECURITY.UNKNOWN.MAX}",
    "DNF: Advisory metadata is incomplete" =>
      "last(/#{template_name}/dnf.advisory.details.complete)=0 or " \
      "last(/#{template_name}/dnf.advisory.cves.complete)=0 or " \
      "last(/#{template_name}/dnf.advisory.issue_dates.complete)=0",
    "DNF: Security package updates lack advisory objects" =>
      "last(/#{template_name}/dnf.updates.security)>(" \
      "last(/#{template_name}/dnf.advisory.packages.critical)+" \
      "last(/#{template_name}/dnf.advisory.packages.important)+" \
      "last(/#{template_name}/dnf.advisory.packages.moderate)+" \
      "last(/#{template_name}/dnf.advisory.packages.low)+" \
      "last(/#{template_name}/dnf.advisory.packages.unknown))"
  }.freeze
  expected_expressions.each do |name, expression|
    unless triggers_by_name.fetch(name).fetch("expression") == expression
      fail_contract("#{template_name} trigger #{name} changed semantics")
    end
  end

  critical_expression = triggers_by_name.fetch("DNF: Critical security advisories are applicable").fetch("expression")
  important_expression = triggers_by_name.fetch("DNF: Important security advisories are applicable").fetch("expression")
  unless critical_expression.include?(">={$DNF.SECURITY.CRITICAL.MIN}") &&
         important_expression.include?("<{$DNF.SECURITY.CRITICAL.MIN}") &&
         important_expression.include?(" and ")
    fail_contract("#{template_name} Critical and Important triggers are not mutually exclusive")
  end

  legacy_security = triggers_by_name.fetch("DNF: Security updates are available")
  unless legacy_security.fetch("expression").include?("dnf.updates.security") &&
         legacy_security.fetch("expression").include?("{$DNF.SECURITY.MIN}")
    fail_contract("#{template_name} legacy security trigger changed")
  end
end

# Run the exact discovery JavaScript from the template against lifecycle and
# trust-boundary fixtures. This supplements import validation, which validates
# the preprocessing shape but does not execute it.
unless advisory_discovery_scripts.uniq.length == 1
  fail_contract("passive and active advisory discovery JavaScript differs")
end
advisory_discovery_javascript = advisory_discovery_scripts.first
lld_macro_values = {
  "{$DNF.ADVISORY.LLD.CRITICAL}" => "0",
  "{$DNF.ADVISORY.LLD.IMPORTANT}" => "0",
  "{$DNF.ADVISORY.LLD.MODERATE}" => "0",
  "{$DNF.ADVISORY.LLD.LOW}" => "0",
  "{$DNF.ADVISORY.LLD.UNKNOWN}" => "0"
}.freeze
fixture_advisories = [
  {
    "id" => "RLSA-2026:100",
    "type" => "security",
    "severity" => "critical",
    "title" => "Critical fixture",
    "issued_at" => "2026-08-01T10:00:00Z",
    "updated_at" => nil,
    "cve_ids" => ["CVE-2026-1001", "CVE-2026-1000", "CVE-2026-1001"],
    "affected_update_nevras" => ["zlib-2.0-1.x86_64", "alpha-2.0-1.x86_64", "zlib-2.0-1.x86_64"]
  },
  {
    "id" => "quote\"\\path:2026",
    "type" => "security",
    "severity" => "important",
    "title" => "Quoted \\\"fixture\\\"",
    "issued_at" => "2026-08-02T10:00:00Z",
    "updated_at" => "2026-08-03T10:00:00Z",
    "cve_ids" => ["CVE-2026-2000"],
    "affected_update_nevras" => ["quoted-1.0-2.x86_64"]
  },
  {
    "id" => "RLSA-2026:300",
    "type" => "security",
    "severity" => "moderate",
    "title" => "Moderate fixture",
    "issued_at" => "2026-08-03T10:00:00Z",
    "updated_at" => nil,
    "cve_ids" => [],
    "affected_update_nevras" => ["moderate-1.0-1.x86_64"]
  },
  {
    "id" => "RLSA-2026:400",
    "type" => "security",
    "severity" => "low",
    "title" => "Low fixture",
    "issued_at" => "2026-08-04T10:00:00Z",
    "updated_at" => nil,
    "cve_ids" => [],
    "affected_update_nevras" => []
  },
  {
    "id" => "RLSA-2026:500",
    "type" => "security",
    "severity" => "unknown",
    "title" => "Unknown fixture",
    "issued_at" => "2026-08-05T10:00:00Z",
    "updated_at" => nil,
    "cve_ids" => [],
    "affected_update_nevras" => ["unknown-1.0-1.x86_64"]
  }
].freeze
complete_discovery_payload = {
  "schema_version" => 1,
  "collection" => {"complete" => true},
  "metadata" => {
    "details_complete" => true,
    "cves_complete" => true,
    "issue_dates_complete" => true
  },
  "summary" => {"advisories" => fixture_advisories.length},
  "advisories" => fixture_advisories
}.freeze

default_discovery = run_advisory_discovery(
  advisory_discovery_javascript, complete_discovery_payload, lld_macro_values
)
unless default_discovery["ok"] && default_discovery["records"] == []
  fail_contract("advisory discovery creates objects with default macros")
end

all_lld_macro_values = lld_macro_values.transform_values { "1" }
all_discovery = run_advisory_discovery(
  advisory_discovery_javascript, complete_discovery_payload, all_lld_macro_values
)
unless all_discovery["ok"] && all_discovery.fetch("records").length == fixture_advisories.length
  fail_contract("advisory discovery does not select every enabled severity")
end
reversed_payload = JSON.parse(JSON.generate(complete_discovery_payload))
reversed_payload["advisories"].reverse!
reversed_discovery = run_advisory_discovery(
  advisory_discovery_javascript, reversed_payload, all_lld_macro_values
)
unless reversed_discovery == all_discovery
  fail_contract("advisory discovery output is not deterministic")
end

unsafe_id = fixture_advisories.fetch(1).fetch("id")
unsafe_record = all_discovery.fetch("records").find { |record| record["id"] == unsafe_id }
expected_safe_id = "a#{unsafe_id.codepoints.map { |code| format('%04x', code) }.join}"
unless unsafe_record && unsafe_record["safe_id"] == expected_safe_id &&
       unsafe_record["safe_id"].match?(/\Aa[0-9a-f]+\z/) &&
       !unsafe_record["safe_id"].include?('"') && !unsafe_record["safe_id"].include?("\\")
  fail_contract("quoted advisory ID was not encoded into a safe deterministic identifier")
end
critical_record = all_discovery.fetch("records").find do |record|
  record["severity"] == "critical"
end
unless JSON.parse(critical_record.fetch("affected_packages")) ==
         ["alpha-2.0-1.x86_64", "zlib-2.0-1.x86_64"] &&
       JSON.parse(critical_record.fetch("cves")) == ["CVE-2026-1000", "CVE-2026-1001"] &&
       critical_record["affected_package_count"] == 2
  fail_contract("advisory discovery did not sort and deduplicate projected lists")
end

disappearance_payload = JSON.parse(JSON.generate(complete_discovery_payload))
disappearance_payload["advisories"].reject! { |advisory| advisory["id"] == unsafe_id }
disappearance_payload["summary"]["advisories"] = disappearance_payload["advisories"].length
disappearance = run_advisory_discovery(
  advisory_discovery_javascript, disappearance_payload, all_lld_macro_values
)
presence_after_disappearance = disappearance.fetch("records").find do |record|
  record["safe_id"] == unsafe_record["safe_id"]
end&.fetch("presence", 0) || 0
unless disappearance["ok"] && presence_after_disappearance.zero?
  fail_contract("a disappeared advisory cannot recover its presence trigger")
end

%w[2 -1 true false].each do |invalid_value|
  invalid_macros = lld_macro_values.merge("{$DNF.ADVISORY.LLD.CRITICAL}" => invalid_value)
  result = run_advisory_discovery(
    advisory_discovery_javascript, complete_discovery_payload, invalid_macros
  )
  fail_contract("invalid advisory discovery macro #{invalid_value.inspect} was accepted") if result["ok"]
end

incomplete_payloads = []
collection_incomplete = JSON.parse(JSON.generate(complete_discovery_payload))
collection_incomplete["collection"]["complete"] = false
incomplete_payloads << collection_incomplete
%w[details_complete cves_complete issue_dates_complete].each do |capability|
  payload = JSON.parse(JSON.generate(complete_discovery_payload))
  payload["metadata"][capability] = false
  incomplete_payloads << payload
end
count_mismatch = JSON.parse(JSON.generate(complete_discovery_payload))
count_mismatch["summary"]["advisories"] += 1
incomplete_payloads << count_mismatch
incomplete_payloads.each_with_index do |payload, index|
  result = run_advisory_discovery(
    advisory_discovery_javascript, payload, all_lld_macro_values
  )
  fail_contract("incomplete advisory discovery fixture #{index} returned false empty data") if result["ok"]
end

# Exercise opening and recovery behavior for the exact expressions locked
# above. Values mirror the dependent-item outputs, including a nil age when no
# vendor timestamp is known.
def advisory_problem_states(values)
  problems = []
  problems << "unavailable" if values.fetch(:collection_complete).zero? || values.fetch(:nodata)
  problems << "critical" if values.fetch(:critical) >= 1
  if values.fetch(:critical) < 1 && values.fetch(:important) >= 1
    problems << "important"
  end
  age = values.fetch(:oldest_age)
  problems << "old" if !age.nil? && age > 604_800
  if values.fetch(:unknown) > 0 || values.fetch(:packages_unknown) > 0
    problems << "unknown"
  end
  unless values.fetch(:details_complete) == 1 &&
         values.fetch(:cves_complete) == 1 &&
         values.fetch(:issue_dates_complete) == 1
    problems << "incomplete"
  end
  linked_packages = %i[
    packages_critical packages_important packages_moderate packages_low packages_unknown
  ].sum { |key| values.fetch(key) }
  problems << "unmatched" if values.fetch(:security_updates) > linked_packages
  problems.sort
end

healthy_advisory_values = {
  collection_complete: 1,
  nodata: false,
  critical: 0,
  important: 0,
  unknown: 0,
  packages_critical: 0,
  packages_important: 0,
  packages_moderate: 0,
  packages_low: 0,
  packages_unknown: 0,
  oldest_age: nil,
  details_complete: 1,
  cves_complete: 1,
  issue_dates_complete: 1,
  security_updates: 0
}.freeze
advisory_scenarios = {
  "healthy" => [{}, []],
  "Critical suppresses Important" => [{ critical: 1, important: 3 }, ["critical"]],
  "Important without Critical" => [{ important: 1 }, ["important"]],
  "old vendor timestamp" => [{ oldest_age: 604_801 }, ["old"]],
  "unknown advisory" => [{ unknown: 1 }, ["unknown"]],
  "unknown package" => [{ packages_unknown: 1 }, ["unknown"]],
  "DNF4 incomplete metadata" => [
    { details_complete: 0, cves_complete: 0, issue_dates_complete: 0 }, ["incomplete"]
  ],
  "collection no data" => [{ nodata: true }, ["unavailable"]],
  "unmatched security update" => [{ security_updates: 2, packages_important: 1 }, ["unmatched"]],
  "recovered clean" => [{}, []]
}.freeze
advisory_scenarios.each do |name, (overrides, expected)|
  actual = advisory_problem_states(healthy_advisory_values.merge(overrides))
  unless actual == expected.sort
    fail_contract("advisory trigger scenario #{name} = #{actual.inspect}, want #{expected.inspect}")
  end
end

apt_templates = templates_by_family.fetch("APT")
expected_apt_keys = %w[
  packages.get
  apt.collection.complete
  apt.collection.duration
  apt.repositories
  apt.updates
  apt.updates.pending
  apt.updates.security
  apt.updates.other
  apt.reboot.pending
  apt.last_update.result
  apt.last_update.timestamp
  apt.metadata.refreshed
  apt.metadata.age
].sort.freeze
expected_apt_macros = %w[
  {$APT.UPDATE.INTERVAL}
  {$APT.NODATA.TIME}
  {$APT.COLLECTION.DURATION.MAX}
  {$APT.SECURITY.MIN}
  {$APT.METADATA.AGE.MAX}
].sort.freeze

apt_templates.each do |template|
  keys = template.fetch("items").map { |item| item.fetch("key") }.sort
  fail_contract("#{template['template']} item set is not APT-safe") unless keys == expected_apt_keys

  macros = template.fetch("macros").map { |macro| macro.fetch("macro") }.sort
  fail_contract("#{template['template']} macro set is incomplete") unless macros == expected_apt_macros

  details = template.fetch("discovery_rules").flat_map do |rule|
    rule.fetch("item_prototypes", [])
  end.find { |prototype| prototype["key"].start_with?("apt.repository.update.details") }
  javascript = details&.fetch("preprocessing", [])&.find do |step|
    step["type"] == "JAVASCRIPT"
  end&.dig("parameters", 0)
  unless javascript&.include?("updates[i].identifier")
    fail_contract("#{template['template']} package details do not consume identifier")
  end
end

puts "Validated combined DNF/APT export UUIDs, parity, and master references"
