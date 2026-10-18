resource "google_pubsub_topic" "budget" {
  project = var.project_id
  name    = "budget-alerts"
  labels  = var.labels

  depends_on = [google_project_service.this]
}

resource "google_monitoring_notification_channel" "budget_email" {
  for_each = toset(var.budget_alert_emails)

  project      = var.project_id
  display_name = "Budget alerts: ${each.value}"
  type         = "email"

  labels = {
    email_address = each.value
  }

  depends_on = [google_project_service.this]
}

resource "google_billing_budget" "project" {
  billing_account = var.billing_account_id
  display_name    = "${var.project_id} monthly budget"

  budget_filter {
    projects               = ["projects/${var.project_number}"]
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.budget_amount)
    }
  }

  dynamic "threshold_rules" {
    for_each = toset(var.budget_thresholds)

    content {
      threshold_percent = threshold_rules.value
      spend_basis       = "CURRENT_SPEND"
    }
  }

  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }

  all_updates_rule {
    pubsub_topic                     = google_pubsub_topic.budget.id
    monitoring_notification_channels = [for c in google_monitoring_notification_channel.budget_email : c.id]
    disable_default_iam_recipients   = false
    schema_version                   = "1.0"
  }

  depends_on = [google_project_service.this]
}
