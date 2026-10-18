package baseline_test

import data.baseline
import rego.v1

# ---- helpers: the shape of `terraform show -json` is `resource_changes[].change.{actions,after,after_unknown}` ----

rc(type, after) := {
	"address": sprintf("%s.x", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

rc_unknown(type, after, unknown) := {
	"address": sprintf("%s.x", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}

plan(changes) := {"resource_changes": changes}

denied(rcs) := {v.rule | some v in baseline.deny with input as plan(rcs)}

messages(rcs) := {v.message | some v in baseline.deny with input as plan(rcs)}

# ---- what counts as a plan ----

test_a_plan_is_recognised if {
	baseline.looks_like_plan with input as {"format_version": "1.2", "planned_values": {"root_module": {}}}
	baseline.looks_like_plan with input as {"format_version": "1.2", "planned_values": {}, "resource_changes": []}
}

test_things_that_are_not_a_plan_are_not_recognised if {
	not baseline.looks_like_plan with input as {}
	not baseline.looks_like_plan with input as {"resource_changes": []}
	not baseline.looks_like_plan with input as {"format_version": "1.0", "values": {"root_module": {}}}
	not baseline.looks_like_plan with input as {"format_version": "1.2", "planned_values": {}, "resource_changes": {}}
	not baseline.looks_like_plan with input as {"format_version": "1.2", "planned_values": {}, "resource_changes": null}
	not baseline.looks_like_plan with input as []
}

# ---- what counts as part of the plan ----

test_a_resource_that_is_only_deleted_is_not_judged if {
	gone := {
		"address": "google_service_account_key.old",
		"type": "google_service_account_key",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}
	count(baseline.deny) == 0 with input as plan([gone])
}

test_a_resource_that_is_replaced_is_judged if {
	replaced := {
		"address": "google_service_account_key.new",
		"type": "google_service_account_key",
		"change": {"actions": ["delete", "create"], "after": {}, "after_unknown": {}},
	}
	denied([replaced]) == {"B003"}
}

test_an_empty_plan_and_a_plan_without_resources_have_no_violations if {
	count(baseline.deny) == 0 with input as {}
	count(baseline.deny) == 0 with input as plan([])
	baseline.report == "" with input as plan([])
}

test_every_rule_has_a_description if {
	count(baseline.rules) == 11
	every id, text in baseline.rules {
		startswith(id, "B")
		count(text) > 10
	}
}

# ---- B001 ----

test_b001_primitive_roles if {
	every type in {"google_project_iam_member", "google_project_iam_binding", "google_folder_iam_member", "google_organization_iam_binding"} {
		every role in {"roles/owner", "roles/editor"} {
			denied([rc(type, {"role": role, "member": "user:a@example.com", "members": ["user:a@example.com"]})]) == {"B001"}
		}
	}
}

test_b001_narrow_roles_and_viewer_pass if {
	every role in {"roles/viewer", "roles/storage.objectViewer", "projects/p/roles/custom"} {
		count(denied([rc("google_project_iam_member", {"role": role, "member": "user:a@example.com"})])) == 0
	}
}

test_b001_message_names_the_role if {
	messages([rc("google_project_iam_member", {"role": "roles/owner", "member": "user:a@example.com"})]) == {"grants roles/owner; use the narrowest predefined or custom role"}
}

# ---- B002 ----

test_b002_public_members if {
	every principal in {"allUsers", "allAuthenticatedUsers"} {
		denied([rc("google_storage_bucket_iam_member", {"role": "roles/storage.objectViewer", "member": principal})]) == {"B002"}
		denied([rc("google_project_iam_binding", {"role": "roles/viewer", "members": ["user:a@example.com", principal]})]) == {"B002"}
		denied([rc("google_cloud_run_service_iam_member", {"role": "roles/run.invoker", "member": principal})]) == {"B002"}
	}
}

test_b002_named_principals_pass if {
	count(denied([rc("google_storage_bucket_iam_member", {"role": "roles/storage.objectViewer", "member": "group:team@example.com"})])) == 0
	count(denied([rc("google_project_iam_binding", {"role": "roles/viewer", "members": ["serviceAccount:a@p.iam.gserviceaccount.com"]})])) == 0
}

test_b002_a_member_that_is_not_known_yet_is_not_a_violation if {
	count(denied([rc_unknown("google_storage_bucket_iam_member", {"role": "roles/x.y"}, {"member": true})])) == 0
}

test_b002_resources_that_are_not_iam_bindings_are_ignored if {
	count(denied([rc("google_pubsub_topic", {"member": "allUsers"})])) == 0
}

# ---- B003 ----

test_b003_service_account_keys if {
	denied([rc("google_service_account_key", {"service_account_id": "x"})]) == {"B003"}
}

# ---- B004 ----

good_bucket := {"uniform_bucket_level_access": true, "public_access_prevention": "enforced"}

test_b004_a_good_bucket_passes if {
	count(denied([rc("google_storage_bucket", good_bucket)])) == 0
}

test_b004_uniform_access_must_be_true if {
	every value in {false, null} {
		denied([rc("google_storage_bucket", object.union(good_bucket, {"uniform_bucket_level_access": value}))]) == {"B004"}
	}
	denied([rc("google_storage_bucket", {"public_access_prevention": "enforced"})]) == {"B004"}
	messages([rc("google_storage_bucket", object.union(good_bucket, {"uniform_bucket_level_access": false}))]) == {"uniform_bucket_level_access is not true"}
}

test_b004_public_access_prevention_must_be_enforced if {
	every value in {"inherited", null} {
		messages([rc("google_storage_bucket", object.union(good_bucket, {"public_access_prevention": value}))]) == {"public_access_prevention is not \"enforced\""}
	}
	messages([rc("google_storage_bucket", {"uniform_bucket_level_access": true})]) == {"public_access_prevention is not \"enforced\""}
}

test_b004_both_missing_is_two_violations if {
	count(messages([rc("google_storage_bucket", {})])) == 2
}

test_b004_unknown_values_are_not_violations if {
	count(denied([rc_unknown("google_storage_bucket", {}, {"uniform_bucket_level_access": true, "public_access_prevention": true})])) == 0
}

# ---- B005 ----

fw(after) := rc("google_compute_firewall", object.union({"source_ranges": ["0.0.0.0/0"]}, after))

test_b005_ssh_and_rdp_from_anywhere if {
	messages([fw({"allow": [{"protocol": "tcp", "ports": ["22"]}]})]) == {"allows tcp/22 from 0.0.0.0/0"}
	messages([fw({"allow": [{"protocol": "tcp", "ports": ["3389"]}]})]) == {"allows tcp/3389 from 0.0.0.0/0"}
	count(messages([fw({"allow": [{"protocol": "tcp", "ports": ["22", "3389", "443"]}]})])) == 2
}

test_b005_a_range_says_which_admin_port_it_covers if {
	messages([fw({"allow": [{"protocol": "tcp", "ports": ["3380-3400"]}]})]) == {"allows tcp/3380-3400 (includes 3389) from 0.0.0.0/0"}
	messages([fw({"allow": [{"protocol": "tcp", "ports": ["0-65535"]}]})]) == {"allows tcp/0-65535 (includes 22) from 0.0.0.0/0", "allows tcp/0-65535 (includes 3389) from 0.0.0.0/0"}
}

test_b005_port_ranges_that_cover_an_admin_port if {
	every spec in {"20-30", "22-22", "0-65535", "3000-4000"} {
		denied([fw({"allow": [{"protocol": "tcp", "ports": [spec]}]})]) == {"B005"}
	}
	every spec in {"23-30", "80", "8000-9000", "443-444"} {
		count(denied([fw({"allow": [{"protocol": "tcp", "ports": [spec]}]})])) == 0
	}
}

test_b005_all_ports_and_all_protocols if {
	messages([fw({"allow": [{"protocol": "tcp"}]})]) == {"allows all tcp ports from 0.0.0.0/0"}
	messages([fw({"allow": [{"protocol": "udp", "ports": []}]})]) == {"allows all udp ports from 0.0.0.0/0"}
	messages([fw({"allow": [{"protocol": "all"}]})]) == {"allows all protocols from 0.0.0.0/0"}
}

test_b005_web_ports_icmp_and_udp_22_pass if {
	count(denied([fw({"allow": [{"protocol": "tcp", "ports": ["80", "443"]}, {"protocol": "icmp"}]})])) == 0
	count(denied([fw({"allow": [{"protocol": "udp", "ports": ["22"]}]})])) == 0
}

test_b005_ipv6_anywhere_counts if {
	messages([fw({"source_ranges": ["::/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}]})]) == {"allows tcp/22 from ::/0"}
}

test_b005_a_private_source_a_disabled_rule_and_egress_pass if {
	count(denied([fw({"source_ranges": ["10.0.0.0/8"], "allow": [{"protocol": "tcp", "ports": ["22"]}]})])) == 0
	count(denied([fw({"disabled": true, "allow": [{"protocol": "tcp", "ports": ["22"]}]})])) == 0
	count(denied([fw({"direction": "EGRESS", "allow": [{"protocol": "tcp", "ports": ["22"]}]})])) == 0
}

test_b005_a_rule_without_allow_blocks_passes if {
	count(denied([fw({"deny": [{"protocol": "all"}]})])) == 0
	count(denied([rc("google_compute_firewall", {"source_ranges": null, "allow": null})])) == 0
}

# ---- B006 ----

budget(rules, updates) := rc("google_billing_budget", {"threshold_rules": rules, "all_updates_rule": updates})

topic_rule := [{"pubsub_topic": "projects/p/topics/t", "monitoring_notification_channels": []}]

good_thresholds := [{"threshold_percent": 0.5}, {"threshold_percent": 1}]

test_b006_a_good_budget_passes if {
	count(denied([budget(good_thresholds, topic_rule)])) == 0
}

test_b006_early_warning if {
	messages([budget([{"threshold_percent": 0.8}, {"threshold_percent": 1}], topic_rule)]) == {"has no threshold at or below 50 %, so there is no early warning"}
	count(denied([budget([{"threshold_percent": 0.5}, {"threshold_percent": 1}], topic_rule)])) == 0
	count(denied([budget([{"threshold_percent": 0.2}, {"threshold_percent": 1.2}], topic_rule)])) == 0
}

test_b006_full_warning if {
	messages([budget([{"threshold_percent": 0.5}, {"threshold_percent": 0.9}], topic_rule)]) == {"has no threshold at or above 100 %"}
}

test_b006_no_thresholds_is_both_problems if {
	count(messages([budget([], topic_rule)])) == 2
}

test_b006_a_notification_target_is_needed if {
	bad := "names no notification target (a Pub/Sub topic or notification channels) in all_updates_rule"
	messages([budget(good_thresholds, [])]) == {bad}
	messages([budget(good_thresholds, null)]) == {bad}
	messages([budget(good_thresholds, [{"pubsub_topic": "", "monitoring_notification_channels": []}])]) == {bad}
	messages([budget(good_thresholds, [{"pubsub_topic": null, "monitoring_notification_channels": null}])]) == {bad}
}

test_b006_channels_alone_are_a_target if {
	count(denied([budget(good_thresholds, [{"pubsub_topic": "", "monitoring_notification_channels": ["projects/p/notificationChannels/1"]}])])) == 0
}

test_b006_a_topic_that_is_not_known_yet_is_a_target if {
	b := rc_unknown("google_billing_budget", {"threshold_rules": good_thresholds, "all_updates_rule": [{"monitoring_notification_channels": []}]}, {"all_updates_rule": [{"pubsub_topic": true}]})
	count(denied([b])) == 0
}

test_b006_channels_that_are_not_known_yet_are_a_target if {
	rule := [{"pubsub_topic": "", "monitoring_notification_channels": [null]}]
	every unknown in {true, [true]} {
		b := rc_unknown("google_billing_budget", {"threshold_rules": good_thresholds, "all_updates_rule": [{"pubsub_topic": "", "monitoring_notification_channels": []}]}, {"all_updates_rule": [{"monitoring_notification_channels": unknown}]})
		count(denied([b])) == 0
	}
	count(denied([budget(good_thresholds, rule)])) == 0
}

test_b006_unknown_that_is_not_a_target_is_still_a_violation if {
	b := rc_unknown("google_billing_budget", {"threshold_rules": good_thresholds, "all_updates_rule": [{"pubsub_topic": "", "monitoring_notification_channels": []}]}, {"all_updates_rule": [{"monitoring_notification_channels": []}]})
	denied([b]) == {"B006"}
}

# ---- B007 ----

test_b007_sink_needs_its_own_writer_identity if {
	every value in {false, null} {
		denied([rc("google_logging_project_sink", {"unique_writer_identity": value})]) == {"B007"}
	}
	denied([rc("google_logging_project_sink", {})]) == {"B007"}
	count(denied([rc("google_logging_project_sink", {"unique_writer_identity": true})])) == 0
	count(denied([rc_unknown("google_logging_project_sink", {}, {"unique_writer_identity": true})])) == 0
}

test_b007_excluding_audit_logs if {
	every type in {"google_logging_project_exclusion", "google_logging_folder_exclusion", "google_logging_organization_exclusion"} {
		denied([rc(type, {"filter": "logName:\"cloudaudit.googleapis.com\""})]) == {"B007"}
	}
	messages([rc("google_logging_project_exclusion", {"filter": "protoPayload.serviceName=\"cloudaudit.googleapis.com\""})]) == {"excludes audit logs from the log router"}
}

test_b007_other_exclusions_and_disabled_ones_pass if {
	count(denied([rc("google_logging_project_exclusion", {"filter": "resource.type=\"gce_instance\" AND severity<ERROR"})])) == 0
	count(denied([rc("google_logging_project_exclusion", {"filter": "logName:\"cloudaudit.googleapis.com\"", "disabled": true})])) == 0
	count(denied([rc("google_logging_project_exclusion", {})])) == 0
}

# ---- B008 ----

org_policy(name, rules) := rc("google_org_policy_policy", {"name": name, "spec": [{"rules": rules}]})

test_b008_relaxing_a_protected_constraint if {
	every constraint in {"iam.disableServiceAccountKeyCreation", "storage.publicAccessPrevention", "compute.requireOsLogin", "sql.restrictPublicIp"} {
		name := sprintf("projects/p/policies/%s", [constraint])
		messages([org_policy(name, [{"enforce": "FALSE"}])]) == {sprintf("relaxes %s", [constraint])}
		messages([org_policy(name, [{"allow_all": "TRUE"}])]) == {sprintf("relaxes %s", [constraint])}
	}
}

test_b008_enforcing_and_other_constraints_pass if {
	count(denied([org_policy("projects/p/policies/iam.disableServiceAccountKeyCreation", [{"enforce": "TRUE"}])])) == 0
	count(denied([org_policy("projects/p/policies/compute.vmExternalIpAccess", [{"deny_all": "TRUE"}])])) == 0
	count(denied([org_policy("projects/p/policies/gcp.resourceLocations", [{"allow_all": "TRUE"}])])) == 0
	count(denied([org_policy("projects/p/policies/iam.disableServiceAccountKeyCreation", [{"values": [{"allowed_values": ["x"]}]}])])) == 0
}

test_b008_a_conditional_relaxation_counts if {
	rules := [{"enforce": "TRUE"}, {"enforce": "FALSE", "condition": [{"expression": "resource.matchTag('a/b', 'c')"}]}]
	denied([org_policy("projects/p/policies/compute.requireOsLogin", rules)]) == {"B008"}
}

test_b008_legacy_resources if {
	every type in {"google_project_organization_policy", "google_folder_organization_policy", "google_organization_policy"} {
		denied([rc(type, {"constraint": "constraints/iam.disableServiceAccountKeyCreation", "boolean_policy": [{"enforced": false}]})]) == {"B008"}
		denied([rc(type, {"constraint": "iam.disableServiceAccountKeyCreation", "boolean_policy": [{"enforced": false}]})]) == {"B008"}
		count(denied([rc(type, {"constraint": "constraints/iam.disableServiceAccountKeyCreation", "boolean_policy": [{"enforced": true}]})])) == 0
		count(denied([rc(type, {"constraint": "constraints/gcp.resourceLocations", "boolean_policy": [{"enforced": false}]})])) == 0
	}
}

# ---- B009 ----

test_b009_external_ip if {
	messages([rc("google_compute_instance", {"network_interface": [{"access_config": [{}]}]})]) == {"has an external IP address (access_config); reach it through IAP or Cloud NAT instead"}
	messages([rc("google_compute_instance", {"network_interface": [{"network": "n"}, {"access_config": [{"nat_ip": "1.2.3.4"}]}]})]) == {"has an external IP address (access_config); reach it through IAP or Cloud NAT instead"}
}

test_b009_internal_only_passes if {
	count(denied([rc("google_compute_instance", {"network_interface": [{"network": "n", "access_config": []}], "metadata": null})])) == 0
	count(denied([rc("google_compute_instance", {"network_interface": [{"network": "n"}]})])) == 0
}

test_b009_os_login_off if {
	every value in {"FALSE", "false", "False"} {
		messages([rc("google_compute_instance", {"network_interface": [], "metadata": {"enable-oslogin": value}})]) == {"switches OS Login off (metadata enable-oslogin)"}
	}
	count(denied([rc("google_compute_instance", {"network_interface": [], "metadata": {"enable-oslogin": "TRUE"}})])) == 0
	count(denied([rc("google_compute_instance", {"network_interface": [], "metadata": {"other": "x"}})])) == 0
}

# ---- B010 ----

test_b010_authoritative_policies if {
	every type in {"google_project_iam_policy", "google_folder_iam_policy", "google_organization_iam_policy"} {
		denied([rc(type, {})]) == {"B010"}
	}
	count(denied([rc("google_project_iam_member", {"role": "roles/viewer", "member": "user:a@example.com"})])) == 0
}

# ---- B011 ----

sql(networks) := rc("google_sql_database_instance", {"settings": [{"ip_configuration": [{"authorized_networks": networks}]}]})

test_b011_world_open_database if {
	messages([sql([{"value": "0.0.0.0/0", "name": "all"}])]) == {"authorizes 0.0.0.0/0 to connect"}
	denied([sql([{"value": "10.0.0.0/8"}, {"value": "::/0"}])]) == {"B011"}
}

test_b011_private_networks_pass if {
	count(denied([sql([{"value": "10.0.0.0/8"}])])) == 0
	count(denied([sql([])])) == 0
	count(denied([rc("google_sql_database_instance", {"settings": [{"ip_configuration": []}]})])) == 0
}

# ---- the report ----

test_the_report_has_one_sorted_line_per_violation if {
	rcs := [
		{"address": "google_service_account_key.k", "type": "google_service_account_key", "change": {"actions": ["create"], "after": {}, "after_unknown": {}}},
		{"address": "module.m.google_project_iam_member.o", "type": "google_project_iam_member", "change": {"actions": ["create"], "after": {"role": "roles/owner", "member": "allUsers"}, "after_unknown": {}}},
	]
	baseline.report == concat("\n", [
		"B001 module.m.google_project_iam_member.o: grants roles/owner; use the narrowest predefined or custom role",
		"B002 module.m.google_project_iam_member.o: grants a role to allUsers, which is anyone on the internet",
		"B003 google_service_account_key.k: creates a service account key; use workload identity federation or an attached service account",
	]) with input as plan(rcs)
}

test_the_same_violation_twice_is_one_line if {
	bucket := {"address": "google_storage_bucket.b", "type": "google_storage_bucket", "change": {"actions": ["create"], "after": {"uniform_bucket_level_access": true, "public_access_prevention": "inherited"}, "after_unknown": {}}}
	count(baseline.deny) == 1 with input as plan([bucket, bucket])
}
