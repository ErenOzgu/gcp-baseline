# Runs with `terraform test` (1.7 or later) and needs no credentials: the google provider is mocked and every
# run only plans. The bad inputs must be refused by the variable validations, with nothing created.
mock_provider "google" {}

variables {
  project_id         = "demo-baseline-1234"
  project_number     = "123456789012"
  billing_account_id = "01ABCD-234567-89EFGH"
  budget_amount      = 200
  audit_bucket_name  = "demo-baseline-1234-audit-logs"
}

run "defaults" {
  command = plan

  assert {
    condition     = length(google_org_policy_policy.enforced) == 7
    error_message = "the seven boolean constraints are enforced by default"
  }

  assert {
    condition     = length(google_org_policy_policy.no_external_ip) == 1
    error_message = "external IPs are denied by default"
  }

  assert {
    condition     = length(google_project_service.this) == 7
    error_message = "the seven APIs the baseline needs are enabled by default"
  }

  assert {
    condition     = output.enforced_constraints == sort(concat(var.enforced_boolean_constraints, ["compute.vmExternalIpAccess"]))
    error_message = "the output lists every enforced constraint, sorted"
  }

  assert {
    condition     = length(google_service_account.workload) == 0 && length(google_project_iam_member.workload) == 0 && length(google_project_iam_member.group) == 0
    error_message = "no identities are created unless asked for"
  }

  assert {
    condition     = google_storage_bucket.audit.uniform_bucket_level_access && google_storage_bucket.audit.public_access_prevention == "enforced"
    error_message = "the audit bucket is closed to the public"
  }

  assert {
    condition     = google_storage_bucket.audit.retention_policy[0].retention_period == 365 * 86400 && !google_storage_bucket.audit.retention_policy[0].is_locked
    error_message = "the audit bucket keeps objects for a year and the lock is off by default"
  }

  assert {
    condition     = google_logging_project_sink.audit.unique_writer_identity
    error_message = "the sink writes with its own identity"
  }

  assert {
    condition     = length(google_billing_budget.project.threshold_rules) == 4
    error_message = "three thresholds on current spend plus one forecast"
  }
}

run "switches" {
  command = plan

  variables {
    deny_external_ips    = false
    enable_apis          = false
    lock_audit_retention = true
    audit_retention_days = 90
  }

  assert {
    condition     = length(google_org_policy_policy.no_external_ip) == 0 && length(google_project_service.this) == 0
    error_message = "the switches turn the external IP denial and the API enabling off"
  }

  assert {
    condition     = !contains(output.enforced_constraints, "compute.vmExternalIpAccess")
    error_message = "a constraint that is not enforced is not listed"
  }

  assert {
    condition     = google_storage_bucket.audit.retention_policy[0].is_locked && google_storage_bucket.audit.retention_policy[0].retention_period == 90 * 86400
    error_message = "the retention days and the lock follow the variables"
  }
}

run "identities" {
  command = plan

  variables {
    service_accounts = {
      "ci-deployer" = {
        display_name = "CI deployer"
        roles        = ["roles/storage.objectAdmin", "roles/run.developer"]
      }
      "app-runtime" = {
        display_name = "Application runtime"
        roles        = ["roles/logging.logWriter"]
      }
    }
    group_roles = {
      "roles/viewer"         = ["engineering@example.com"]
      "roles/logging.viewer" = ["engineering@example.com", "support@example.com"]
    }
  }

  assert {
    condition     = length(google_service_account.workload) == 2
    error_message = "one service account per entry"
  }

  assert {
    condition     = length(google_project_iam_member.workload) == 3
    error_message = "one binding per role of each service account"
  }

  assert {
    condition     = length(google_project_iam_member.group) == 3
    error_message = "one binding per role and group"
  }
}

run "alerts_by_mail" {
  command = plan

  variables {
    budget_alert_emails = ["finops@example.com", "owner@example.com"]
  }

  assert {
    condition     = length(google_monitoring_notification_channel.budget_email) == 2
    error_message = "one notification channel per address"
  }
}

# ---- bad input is refused ----

run "project_id_with_capitals" {
  command = plan
  variables {
    project_id = "Demo-Project"
  }
  expect_failures = [var.project_id]
}

run "project_id_too_short" {
  command = plan
  variables {
    project_id = "demo"
  }
  expect_failures = [var.project_id]
}

run "project_number_is_not_a_number" {
  command = plan
  variables {
    project_number = "demo-baseline-1234"
  }
  expect_failures = [var.project_number]
}

run "billing_account_in_the_wrong_shape" {
  command = plan
  variables {
    billing_account_id = "billingAccounts/01ABCD-234567-89EFGH"
  }
  expect_failures = [var.billing_account_id]
}

run "budget_of_zero" {
  command = plan
  variables {
    budget_amount = 0
  }
  expect_failures = [var.budget_amount]
}

run "budget_with_cents" {
  command = plan
  variables {
    budget_amount = 99.5
  }
  expect_failures = [var.budget_amount]
}

run "currency_in_lower_case" {
  command = plan
  variables {
    budget_currency = "eur"
  }
  expect_failures = [var.budget_currency]
}

run "thresholds_without_an_early_warning" {
  command = plan
  variables {
    budget_thresholds = [0.8, 1.0]
  }
  expect_failures = [var.budget_thresholds]
}

run "thresholds_without_a_full_alert" {
  command = plan
  variables {
    budget_thresholds = [0.5, 0.9]
  }
  expect_failures = [var.budget_thresholds]
}

run "no_thresholds" {
  command = plan
  variables {
    budget_thresholds = []
  }
  expect_failures = [var.budget_thresholds]
}

run "alert_address_is_not_an_address" {
  command = plan
  variables {
    budget_alert_emails = ["finops"]
  }
  expect_failures = [var.budget_alert_emails]
}

run "bucket_name_starting_with_goog" {
  command = plan
  variables {
    audit_bucket_name = "google-audit-logs"
  }
  expect_failures = [var.audit_bucket_name]
}

run "bucket_name_in_capitals" {
  command = plan
  variables {
    audit_bucket_name = "Audit-Logs"
  }
  expect_failures = [var.audit_bucket_name]
}

run "retention_under_thirty_days" {
  command = plan
  variables {
    audit_retention_days = 7
  }
  expect_failures = [var.audit_retention_days]
}

run "constraint_with_a_prefix" {
  command = plan
  variables {
    enforced_boolean_constraints = ["constraints/compute.requireOsLogin"]
  }
  expect_failures = [var.enforced_boolean_constraints]
}

run "service_account_with_owner" {
  command = plan
  variables {
    service_accounts = {
      "ci-deployer" = { display_name = "CI", roles = ["roles/owner"] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "service_account_with_editor" {
  command = plan
  variables {
    service_accounts = {
      "ci-deployer" = { display_name = "CI", roles = ["roles/viewer", "roles/editor"] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "service_account_without_roles" {
  command = plan
  variables {
    service_accounts = {
      "ci-deployer" = { display_name = "CI", roles = [] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "service_account_with_a_duplicate_role" {
  command = plan
  variables {
    service_accounts = {
      "ci-deployer" = { display_name = "CI", roles = ["roles/viewer", "roles/viewer"] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "service_account_id_too_short" {
  command = plan
  variables {
    service_accounts = {
      "ci" = { display_name = "CI", roles = ["roles/viewer"] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "role_written_the_wrong_way" {
  command = plan
  variables {
    service_accounts = {
      "ci-deployer" = { display_name = "CI", roles = ["storage.objectAdmin"] }
    }
  }
  expect_failures = [var.service_accounts]
}

run "group_with_owner" {
  command = plan
  variables {
    group_roles = {
      "roles/owner" = ["engineering@example.com"]
    }
  }
  expect_failures = [var.group_roles]
}

run "group_listed_twice" {
  command = plan
  variables {
    group_roles = {
      "roles/viewer" = ["engineering@example.com", "engineering@example.com"]
    }
  }
  expect_failures = [var.group_roles]
}

run "group_with_a_prefix" {
  command = plan
  variables {
    group_roles = {
      "roles/viewer" = ["group:engineering@example.com"]
    }
  }
  expect_failures = [var.group_roles]
}
