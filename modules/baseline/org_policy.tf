resource "google_org_policy_policy" "enforced" {
  for_each = toset(var.enforced_boolean_constraints)

  name   = "projects/${var.project_id}/policies/${each.value}"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }

  depends_on = [google_project_service.this]
}

resource "google_org_policy_policy" "no_external_ip" {
  count = var.deny_external_ips ? 1 : 0

  name   = "projects/${var.project_id}/policies/compute.vmExternalIpAccess"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      deny_all = "TRUE"
    }
  }

  depends_on = [google_project_service.this]
}
