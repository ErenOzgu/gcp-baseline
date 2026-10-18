# A project baseline with dummy values. `terraform plan` needs no credentials worth having:
# CI plans it with a made-up access token, because creating these resources is never attempted.
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
  project = "demo-baseline-1234"
  region  = "europe-west3"
}

module "baseline" {
  source = "../../modules/baseline"

  project_id         = "demo-baseline-1234"
  project_number     = "123456789012"
  billing_account_id = "01ABCD-234567-89EFGH"

  budget_amount       = 200
  budget_currency     = "EUR"
  budget_alert_emails = ["finops@example.com"]

  audit_bucket_name    = "demo-baseline-1234-audit-logs"
  audit_retention_days = 365

  service_accounts = {
    "ci-deployer" = {
      display_name = "CI deployer"
      roles        = ["roles/storage.objectAdmin", "roles/run.developer"]
    }
    "app-runtime" = {
      display_name = "Application runtime"
      roles        = ["roles/logging.logWriter", "roles/monitoring.metricWriter"]
    }
  }

  group_roles = {
    "roles/viewer"                 = ["engineering@example.com"]
    "roles/logging.viewer"         = ["engineering@example.com", "support@example.com"]
    "roles/billing.projectManager" = ["finops@example.com"]
  }

  labels = {
    managed-by = "terraform"
    baseline   = "gcp-baseline"
  }
}

output "enforced_constraints" {
  value = module.baseline.enforced_constraints
}
