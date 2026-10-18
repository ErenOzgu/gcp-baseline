locals {
  apis = [
    "billingbudgets.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "orgpolicy.googleapis.com",
    "pubsub.googleapis.com",
    "storage.googleapis.com",
  ]
}

resource "google_project_service" "this" {
  for_each = var.enable_apis ? toset(local.apis) : toset([])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
