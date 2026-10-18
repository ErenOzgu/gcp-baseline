resource "google_storage_bucket" "audit" {
  project  = var.project_id
  name     = var.audit_bucket_name
  location = var.audit_bucket_location
  labels   = var.labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = var.audit_retention_days * 86400
    is_locked        = var.lock_audit_retention
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  depends_on = [google_project_service.this]
}

resource "google_logging_project_sink" "audit" {
  project     = var.project_id
  name        = "audit-logs-to-storage"
  destination = "storage.googleapis.com/${google_storage_bucket.audit.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""

  unique_writer_identity = true

  depends_on = [google_project_service.this]
}

resource "google_storage_bucket_iam_member" "audit_writer" {
  bucket = google_storage_bucket.audit.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit.writer_identity
}
