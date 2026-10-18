# METADATA
# title: GCP baseline
# description: >-
#   Rules for a Terraform plan (the JSON from `terraform show -json plan`). A rule that fires adds an object
#   {rule, resource, message} to `deny`. `report` is the same, one sorted line per violation, empty when there is none.
package baseline

import rego.v1

# One line per rule, used by the README table (scripts/rules-table.sh) and checked against it.
rules := {
	"B001": "No Owner or Editor role on a project, folder or organization",
	"B002": "No IAM binding to allUsers or allAuthenticatedUsers",
	"B003": "No service account keys",
	"B004": "Storage buckets use uniform bucket-level access and enforce public access prevention",
	"B005": "No firewall rule opens SSH, RDP, all ports or all protocols to the internet",
	"B006": "A budget warns early (50 % or lower), warns at 100 % or more, and names a notification target",
	"B007": "Log sinks have their own writer identity and nothing excludes audit logs",
	"B008": "No organization policy relaxes a protected constraint",
	"B009": "Compute instances have no external IP and do not switch OS Login off",
	"B010": "No authoritative IAM policy resource",
	"B011": "Cloud SQL does not authorize 0.0.0.0/0",
}

# Whether the input looks like `terraform show -json PLAN`. scripts/check-plan.sh refuses anything else, because an
# empty or wrong file would otherwise be reported as "no violations".
looks_like_plan if {
	is_string(input.format_version)
	is_object(input.planned_values)
	is_array(object.get(input, "resource_changes", []))
}

# Managed resources that still exist after the apply: anything that is not only being deleted.
live contains rc if {
	some rc in input.resource_changes
	rc.change.actions != ["delete"]
}

violation(rc, rule, message) := {"rule": rule, "resource": rc.address, "message": message}

# A value the plan cannot know yet (for example an ID of something created in the same plan) is given the
# benefit of the doubt: the rule cannot judge it, and says so in the README.
_unknown(rc, key) if rc.change.after_unknown[key] == true

_true_or_unknown(rc, key) if rc.change.after[key] == true

_true_or_unknown(rc, key) if _unknown(rc, key)

_world := {"0.0.0.0/0", "::/0"}

# ---- B001 ------------------------------------------------------------------------------------------------------

_iam_grants := {
	"google_project_iam_member", "google_project_iam_binding",
	"google_folder_iam_member", "google_folder_iam_binding",
	"google_organization_iam_member", "google_organization_iam_binding",
}

_primitive_roles := {"roles/owner", "roles/editor"}

deny contains v if {
	some rc in live
	rc.type in _iam_grants
	role := rc.change.after.role
	role in _primitive_roles
	v := violation(rc, "B001", sprintf("grants %s; use the narrowest predefined or custom role", [role]))
}

# ---- B002 ------------------------------------------------------------------------------------------------------

_public_principals := {"allUsers", "allAuthenticatedUsers"}

_principals(after) := {m | m := after.member} | {m | some m in after.members}

deny contains v if {
	some rc in live
	regex.match(`^google_.+_iam_(member|binding)$`, rc.type)
	some principal in _principals(rc.change.after)
	principal in _public_principals
	v := violation(rc, "B002", sprintf("grants a role to %s, which is anyone on the internet", [principal]))
}

# ---- B003 ------------------------------------------------------------------------------------------------------

deny contains v if {
	some rc in live
	rc.type == "google_service_account_key"
	v := violation(rc, "B003", "creates a service account key; use workload identity federation or an attached service account")
}

# ---- B004 ------------------------------------------------------------------------------------------------------

deny contains v if {
	some rc in live
	rc.type == "google_storage_bucket"
	not _true_or_unknown(rc, "uniform_bucket_level_access")
	v := violation(rc, "B004", "uniform_bucket_level_access is not true")
}

deny contains v if {
	some rc in live
	rc.type == "google_storage_bucket"
	not rc.change.after.public_access_prevention == "enforced"
	not _unknown(rc, "public_access_prevention")
	v := violation(rc, "B004", "public_access_prevention is not \"enforced\"")
}

# ---- B005 ------------------------------------------------------------------------------------------------------

_admin_ports := {22, 3389}

_covers(spec, port) if spec == sprintf("%d", [port])

_covers(spec, port) if {
	parts := split(spec, "-")
	count(parts) == 2
	to_number(parts[0]) <= port
	port <= to_number(parts[1])
}

_label(spec, port) := sprintf("tcp/%s", [spec]) if spec == sprintf("%d", [port])

_label(spec, port) := sprintf("tcp/%s (includes %d)", [spec, port]) if spec != sprintf("%d", [port])

_ports(allow) := object.get(allow, "ports", [])

# What one allow block opens to whoever can reach it.
_exposed(allow) := e if {
	e := ({"all protocols" | allow.protocol == "all"} | {sprintf("all %s ports", [allow.protocol]) |
		allow.protocol in {"tcp", "udp", "sctp"}
		count(_ports(allow)) == 0
	}) | {_label(spec, port) |
		allow.protocol == "tcp"
		some spec in _ports(allow)
		some port in _admin_ports
		_covers(spec, port)
	}
}

deny contains v if {
	some rc in live
	rc.type == "google_compute_firewall"
	after := rc.change.after
	object.get(after, "direction", "INGRESS") == "INGRESS"
	object.get(after, "disabled", false) != true
	some source in object.get(after, "source_ranges", [])
	source in _world
	some allow in object.get(after, "allow", [])
	some exposed in _exposed(allow)
	v := violation(rc, "B005", sprintf("allows %s from %s", [exposed, source]))
}

# ---- B006 ------------------------------------------------------------------------------------------------------

_thresholds(rc) := {t | some rule in rc.change.after.threshold_rules; t := rule.threshold_percent}

deny contains v if {
	some rc in live
	rc.type == "google_billing_budget"
	not _early_warning(rc)
	v := violation(rc, "B006", "has no threshold at or below 50 %, so there is no early warning")
}

_early_warning(rc) if {
	some t in _thresholds(rc)
	t <= 0.5
}

deny contains v if {
	some rc in live
	rc.type == "google_billing_budget"
	not _full_warning(rc)
	v := violation(rc, "B006", "has no threshold at or above 100 %")
}

_full_warning(rc) if {
	some t in _thresholds(rc)
	t >= 1
}

deny contains v if {
	some rc in live
	rc.type == "google_billing_budget"
	not _notifies(rc)
	v := violation(rc, "B006", "names no notification target (a Pub/Sub topic or notification channels) in all_updates_rule")
}

_notifies(rc) if {
	some rule in rc.change.after.all_updates_rule
	_target(rule)
}

_notifies(rc) if {
	some i, _ in rc.change.after.all_updates_rule
	_target_unknown(rc.change.after_unknown.all_updates_rule[i])
}

_target(rule) if {
	is_string(rule.pubsub_topic)
	rule.pubsub_topic != ""
}

_target(rule) if count(rule.monitoring_notification_channels) > 0

_target_unknown(unknown) if unknown.pubsub_topic == true

_target_unknown(unknown) if _some(unknown.monitoring_notification_channels)

_some(x) if x == true

_some(x) if {
	is_array(x)
	count(x) > 0
}

# ---- B007 ------------------------------------------------------------------------------------------------------

deny contains v if {
	some rc in live
	rc.type == "google_logging_project_sink"
	not _true_or_unknown(rc, "unique_writer_identity")
	v := violation(rc, "B007", "unique_writer_identity is not true: the sink shares a writer identity with every other sink of the project")
}

_exclusions := {
	"google_logging_project_exclusion",
	"google_logging_folder_exclusion",
	"google_logging_organization_exclusion",
}

deny contains v if {
	some rc in live
	rc.type in _exclusions
	object.get(rc.change.after, "disabled", false) != true
	contains(object.get(rc.change.after, "filter", ""), "cloudaudit.googleapis.com")
	v := violation(rc, "B007", "excludes audit logs from the log router")
}

# ---- B008 ------------------------------------------------------------------------------------------------------

_protected := {
	"iam.disableServiceAccountKeyCreation",
	"iam.disableServiceAccountKeyUpload",
	"storage.uniformBucketLevelAccess",
	"storage.publicAccessPrevention",
	"compute.requireOsLogin",
	"compute.disableSerialPortAccess",
	"sql.restrictPublicIp",
}

_relaxes(rule) if rule.enforce == "FALSE"

_relaxes(rule) if rule.allow_all == "TRUE"

deny contains v if {
	some rc in live
	rc.type == "google_org_policy_policy"
	parts := split(rc.change.after.name, "/")
	constraint := parts[count(parts) - 1]
	constraint in _protected
	some spec in rc.change.after.spec
	some rule in spec.rules
	_relaxes(rule)
	v := violation(rc, "B008", sprintf("relaxes %s", [constraint]))
}

_legacy_org_policies := {
	"google_project_organization_policy",
	"google_folder_organization_policy",
	"google_organization_policy",
}

deny contains v if {
	some rc in live
	rc.type in _legacy_org_policies
	constraint := trim_prefix(rc.change.after.constraint, "constraints/")
	constraint in _protected
	some policy in rc.change.after.boolean_policy
	policy.enforced == false
	v := violation(rc, "B008", sprintf("relaxes %s", [constraint]))
}

# ---- B009 ------------------------------------------------------------------------------------------------------

deny contains v if {
	some rc in live
	rc.type == "google_compute_instance"
	some interface in rc.change.after.network_interface
	count(object.get(interface, "access_config", [])) > 0
	v := violation(rc, "B009", "has an external IP address (access_config); reach it through IAP or Cloud NAT instead")
}

deny contains v if {
	some rc in live
	rc.type == "google_compute_instance"
	lower(rc.change.after.metadata["enable-oslogin"]) == "false"
	v := violation(rc, "B009", "switches OS Login off (metadata enable-oslogin)")
}

# ---- B010 ------------------------------------------------------------------------------------------------------

_authoritative := {
	"google_project_iam_policy",
	"google_folder_iam_policy",
	"google_organization_iam_policy",
}

deny contains v if {
	some rc in live
	rc.type in _authoritative
	v := violation(rc, "B010", "is an authoritative IAM policy: it replaces every binding on the resource and can lock everyone out; use the _member resources")
}

# ---- B011 ------------------------------------------------------------------------------------------------------

deny contains v if {
	some rc in live
	rc.type == "google_sql_database_instance"
	some settings in rc.change.after.settings
	some ip_configuration in settings.ip_configuration
	some network in ip_configuration.authorized_networks
	network.value in _world
	v := violation(rc, "B011", sprintf("authorizes %s to connect", [network.value]))
}

# ---- the report ------------------------------------------------------------------------------------------------

report := concat("\n", sort([sprintf("%s %s: %s", [v.rule, v.resource, v.message]) | some v in deny]))
