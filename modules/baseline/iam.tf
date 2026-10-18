locals {
  service_account_roles = merge({}, [
    for sa, cfg in var.service_accounts : {
      for role in cfg.roles : "${sa}|${role}" => { sa = sa, role = role }
    }
  ]...)

  group_bindings = merge({}, [
    for role, groups in var.group_roles : {
      for group in groups : "${role}|${group}" => { role = role, group = group }
    }
  ]...)
}

resource "google_service_account" "workload" {
  for_each = var.service_accounts

  project      = var.project_id
  account_id   = each.key
  display_name = each.value.display_name

  depends_on = [google_project_service.this]
}

resource "google_project_iam_member" "workload" {
  for_each = local.service_account_roles

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.workload[each.value.sa].email}"
}

resource "google_project_iam_member" "group" {
  for_each = local.group_bindings

  project = var.project_id
  role    = each.value.role
  member  = "group:${each.value.group}"
}
