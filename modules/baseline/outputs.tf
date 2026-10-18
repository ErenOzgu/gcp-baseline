output "audit_bucket" {
  description = "Name of the bucket that receives the audit logs."
  value       = google_storage_bucket.audit.name
}

output "audit_sink_writer_identity" {
  description = "Identity the log sink writes with."
  value       = google_logging_project_sink.audit.writer_identity
}

output "budget_name" {
  description = "Resource name of the budget."
  value       = google_billing_budget.project.name
}

output "budget_topic" {
  description = "Pub/Sub topic the budget alerts are published to."
  value       = google_pubsub_topic.budget.id
}

output "service_account_emails" {
  description = "E-mail address of each service account, by account id."
  value       = { for id, sa in google_service_account.workload : id => sa.email }
}

output "enforced_constraints" {
  description = "Organization policy constraints enforced on the project."
  value = sort(concat(
    var.enforced_boolean_constraints,
    var.deny_external_ips ? ["compute.vmExternalIpAccess"] : [],
  ))
}
