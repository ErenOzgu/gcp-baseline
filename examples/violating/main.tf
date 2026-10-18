# Plain resources that each break a rule of policy/baseline.rego, with dummy values.
# Nothing here is ever applied: CI only plans it and expects policy/expected.txt as the report.
terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.8.0"
    }
  }
}

provider "google" {
  project = "demo-violations-1234"
  region  = "europe-west3"
}

# B001: a primitive role
resource "google_project_iam_member" "owner" {
  project = "demo-violations-1234"
  role    = "roles/owner"
  member  = "user:alice@example.com"
}

# B002: a role for everyone on the internet; B004: a bucket without the two protections
resource "google_storage_bucket" "open" {
  project  = "demo-violations-1234"
  name     = "demo-violations-1234-open"
  location = "EU"

  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.open.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# B003: a long-lived key
resource "google_service_account" "legacy" {
  project      = "demo-violations-1234"
  account_id   = "legacy-deployer"
  display_name = "Legacy deployer"
}

resource "google_service_account_key" "legacy" {
  service_account_id = google_service_account.legacy.name
}

# B005: SSH from anywhere, every TCP port from anywhere, and a range that covers RDP
resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "all_tcp" {
  name          = "allow-all-tcp"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
  }
}

resource "google_compute_firewall" "rdp_range" {
  name          = "allow-rdp-range"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3380-3400"]
  }
}

# B006: a budget with no early warning, no alert at 100 % and nobody to tell
resource "google_billing_budget" "quiet" {
  billing_account = "01ABCD-234567-89EFGH"
  display_name    = "quiet budget"

  amount {
    specified_amount {
      currency_code = "EUR"
      units         = "100"
    }
  }

  threshold_rules {
    threshold_percent = 0.8
  }

  threshold_rules {
    threshold_percent = 0.9
  }
}

# B007: a sink that shares the project's writer identity, and an exclusion that drops audit logs
resource "google_logging_project_sink" "shared" {
  project     = "demo-violations-1234"
  name        = "to-storage"
  destination = "storage.googleapis.com/demo-violations-1234-logs"
}

resource "google_logging_project_exclusion" "audit" {
  project = "demo-violations-1234"
  name    = "drop-audit"
  filter  = "logName:\"cloudaudit.googleapis.com\""
}

# B008: relaxed constraints, one with the current resource and one with the legacy one
resource "google_org_policy_policy" "keys" {
  name   = "projects/demo-violations-1234/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/demo-violations-1234"

  spec {
    rules {
      enforce = "FALSE"
    }
  }
}

resource "google_project_organization_policy" "public_access" {
  project    = "demo-violations-1234"
  constraint = "constraints/storage.publicAccessPrevention"

  boolean_policy {
    enforced = false
  }
}

# B009: an external IP and OS Login switched off
resource "google_compute_instance" "bastion" {
  project      = "demo-violations-1234"
  name         = "bastion"
  zone         = "europe-west3-a"
  machine_type = "e2-small"

  metadata = {
    enable-oslogin = "FALSE"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"

    access_config {}
  }
}

# B010: an authoritative policy
data "google_iam_policy" "only_viewer" {
  binding {
    role    = "roles/viewer"
    members = ["user:alice@example.com"]
  }
}

resource "google_project_iam_policy" "authoritative" {
  project     = "demo-violations-1234"
  policy_data = data.google_iam_policy.only_viewer.policy_data
}

# B011: a database that anyone can try to log in to
resource "google_sql_database_instance" "open" {
  project             = "demo-violations-1234"
  name                = "open-db"
  region              = "europe-west3"
  database_version    = "POSTGRES_16"
  deletion_protection = false

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
