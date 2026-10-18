variable "project_id" {
  description = "ID of the project the baseline is applied to."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be 6 to 30 characters: lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen."
  }
}

variable "project_number" {
  description = "Number (not the ID) of the same project. The budget filter needs it."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,15}$", var.project_number))
    error_message = "project_number must be the numeric project number, for example 123456789012."
  }
}

variable "billing_account_id" {
  description = "Billing account that pays for the project, in the form XXXXXX-XXXXXX-XXXXXX."
  type        = string

  validation {
    condition     = can(regex("^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$", var.billing_account_id))
    error_message = "billing_account_id must look like 01ABCD-234567-89EFGH."
  }
}

variable "budget_amount" {
  description = "Monthly budget in whole units of budget_currency."
  type        = number

  validation {
    condition     = var.budget_amount > 0 && var.budget_amount == floor(var.budget_amount)
    error_message = "budget_amount must be a positive whole number."
  }
}

variable "budget_currency" {
  description = "ISO 4217 currency code of the budget. It must be the currency of the billing account."
  type        = string
  default     = "EUR"

  validation {
    condition     = can(regex("^[A-Z]{3}$", var.budget_currency))
    error_message = "budget_currency must be a three-letter currency code such as EUR or USD."
  }
}

variable "budget_thresholds" {
  description = "Fractions of the budget at which an alert is sent on current spend. A forecast alert at 100 % is always added."
  type        = list(number)
  default     = [0.5, 0.8, 1.0]

  validation {
    condition     = length(var.budget_thresholds) > 0 && alltrue([for t in var.budget_thresholds : t > 0 && t <= 2])
    error_message = "budget_thresholds must be a non-empty list of fractions greater than 0 and at most 2."
  }

  validation {
    condition     = anytrue([for t in var.budget_thresholds : t <= 0.5]) && anytrue([for t in var.budget_thresholds : t >= 1])
    error_message = "budget_thresholds needs an early warning (0.5 or lower) and an alert at or above 1.0."
  }
}

variable "budget_alert_emails" {
  description = "E-mail addresses that get a budget alert through Cloud Monitoring notification channels. The alerts are also published to a Pub/Sub topic."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.budget_alert_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "Every entry of budget_alert_emails must be an e-mail address."
  }
}

variable "audit_bucket_name" {
  description = "Globally unique name of the Cloud Storage bucket that receives the audit logs."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", var.audit_bucket_name)) && !startswith(var.audit_bucket_name, "goog")
    error_message = "audit_bucket_name must be 3 to 63 characters of lowercase letters, digits, dots, underscores and hyphens, and must not start with goog."
  }
}

variable "audit_bucket_location" {
  description = "Location of the audit log bucket."
  type        = string
  default     = "EU"
}

variable "audit_retention_days" {
  description = "How long objects in the audit log bucket cannot be deleted or replaced."
  type        = number
  default     = 365

  validation {
    condition     = var.audit_retention_days >= 30 && var.audit_retention_days == floor(var.audit_retention_days)
    error_message = "audit_retention_days must be a whole number of at least 30."
  }
}

variable "lock_audit_retention" {
  description = "Lock the retention policy. A locked policy can never be shortened or removed, not even by an owner, and the bucket can then only be deleted together with the project."
  type        = bool
  default     = false
}

variable "enforced_boolean_constraints" {
  description = "Boolean organization policy constraints to enforce on the project."
  type        = list(string)
  default = [
    "iam.disableServiceAccountKeyCreation",
    "iam.disableServiceAccountKeyUpload",
    "storage.uniformBucketLevelAccess",
    "storage.publicAccessPrevention",
    "compute.requireOsLogin",
    "compute.disableSerialPortAccess",
    "sql.restrictPublicIp",
  ]

  validation {
    condition     = alltrue([for c in var.enforced_boolean_constraints : can(regex("^[a-z]+\\.[A-Za-z]+$", c))])
    error_message = "Constraint names look like compute.requireOsLogin, without a constraints/ prefix."
  }
}

variable "deny_external_ips" {
  description = "Deny external IP addresses on virtual machines of the project (compute.vmExternalIpAccess)."
  type        = bool
  default     = true
}

variable "service_accounts" {
  description = "Service accounts to create, by account id, with the project roles each one gets. Primitive roles are refused."
  type = map(object({
    display_name = string
    roles        = list(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for id, _ in var.service_accounts : can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", id))])
    error_message = "A service account id must be 6 to 30 characters: lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen."
  }

  validation {
    condition     = alltrue([for _, sa in var.service_accounts : length(sa.roles) > 0])
    error_message = "A service account without roles is pointless; give it at least one role or remove it."
  }

  validation {
    condition     = alltrue([for _, sa in var.service_accounts : length(sa.roles) == length(toset(sa.roles))])
    error_message = "A service account lists the same role twice."
  }

  validation {
    condition = alltrue(flatten([
      for _, sa in var.service_accounts : [for r in sa.roles : !contains(["roles/owner", "roles/editor"], r)]
    ]))
    error_message = "roles/owner and roles/editor are not allowed. Pick the narrowest predefined or custom role."
  }

  validation {
    condition = alltrue(flatten([
      for _, sa in var.service_accounts : [for r in sa.roles : can(regex("^(roles|projects/[^/]+/roles|organizations/[0-9]+/roles)/[A-Za-z0-9_.]+$", r))]
    ]))
    error_message = "Roles must be written as roles/NAME, projects/ID/roles/NAME or organizations/NUMBER/roles/NAME."
  }
}

variable "group_roles" {
  description = "Project roles granted to Google groups: role => list of group e-mail addresses. Primitive roles are refused."
  type        = map(list(string))
  default     = {}

  validation {
    condition     = alltrue([for r, _ in var.group_roles : !contains(["roles/owner", "roles/editor"], r)])
    error_message = "roles/owner and roles/editor are not allowed. Pick the narrowest predefined or custom role."
  }

  validation {
    condition     = alltrue([for _, groups in var.group_roles : length(groups) == length(toset(groups))])
    error_message = "A role lists the same group twice."
  }

  validation {
    condition = alltrue(flatten([
      for _, groups in var.group_roles : [for g in groups : can(regex("^[^@\\s:]+@[^@\\s]+\\.[^@\\s]+$", g))]
    ]))
    error_message = "Every group must be given as an e-mail address, without the group: prefix."
  }
}

variable "enable_apis" {
  description = "Enable the Google APIs the baseline needs. They are not disabled again on destroy."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels put on the resources that support them."
  type        = map(string)
  default     = {}
}
