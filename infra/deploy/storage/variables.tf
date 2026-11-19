variable "project_id" {
  description = "Google Cloud project ID that owns the Traceon buckets and service accounts."
  type        = string
}

variable "region" {
  description = "Google Cloud region used by the provider for project resources."
  type        = string
}

variable "bucket_location" {
  description = "Cloud Storage location for the quarantine and evidence buckets."
  type        = string
}

variable "database_tier" {
  description = "Cloud SQL machine tier for this staging-only PostgreSQL instance. db-f1-micro is a shared-core, low-cost development tier without an SLA."
  type        = string
  default     = "db-f1-micro"
}
