terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0, < 9.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "storage" {
  project            = var.project_id
  service            = "storage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "backend" {
  project      = var.project_id
  account_id   = "traceon-backend"
  display_name = "Traceon backend service"
  description  = "Backend API identity for quarantine and evidence objects."
  depends_on   = [google_project_service.iam]
}

resource "google_service_account" "sandbox" {
  project      = var.project_id
  account_id   = "traceon-sandbox"
  display_name = "Traceon isolated scanner host"
  description  = "Host identity for fetching quarantined inputs; sandbox child processes receive no credentials."
  depends_on   = [google_project_service.iam]
}

resource "google_storage_bucket" "quarantine" {
  project                     = var.project_id
  name                        = "${var.project_id}-traceon-quarantine"
  location                    = var.bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  labels = {
    application = "traceon"
    data_class  = "quarantine"
  }

  depends_on = [google_project_service.storage]
}

resource "google_storage_bucket" "evidence" {
  project                     = var.project_id
  name                        = "${var.project_id}-traceon-evidence"
  location                    = var.bucket_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  labels = {
    application = "traceon"
    data_class  = "evidence"
  }

  depends_on = [google_project_service.storage]
}

# Backend objects are immutable-by-default from the application's perspective:
# it can create and read objects but has no bucket-scoped delete permission.
resource "google_storage_bucket_iam_member" "backend_quarantine_create" {
  bucket = google_storage_bucket.quarantine.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_storage_bucket_iam_member" "backend_quarantine_read" {
  bucket = google_storage_bucket.quarantine.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_storage_bucket_iam_member" "sandbox_quarantine_read" {
  bucket = google_storage_bucket.quarantine.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.sandbox.email}"
}

resource "google_storage_bucket_iam_member" "backend_evidence_create" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_storage_bucket_iam_member" "backend_evidence_read" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.backend.email}"
}
