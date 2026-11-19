terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0, < 9.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.7.1, < 4.0.0"
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

resource "google_project_service" "kms" {
  project            = var.project_id
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sqladmin" {
  project            = var.project_id
  service            = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  project            = var.project_id
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifactregistry" {
  project            = var.project_id
  service            = "artifactregistry.googleapis.com"
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

resource "google_artifact_registry_repository" "docker" {
  project       = var.project_id
  location      = var.region
  repository_id = "traceon"
  description   = "Traceon staging container images."
  format        = "DOCKER"

  depends_on = [google_project_service.artifactregistry]
}

resource "google_sql_database_instance" "postgres" {
  project             = var.project_id
  name                = "traceon-staging-pg"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    edition           = "ENTERPRISE"
    tier              = var.database_tier
    availability_type = "ZONAL"
    disk_type         = "PD_HDD"
    disk_size         = 10
    disk_autoresize   = false

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }
  }

  depends_on = [google_project_service.sqladmin]
}

resource "google_sql_database" "app" {
  project  = var.project_id
  name     = "traceon"
  instance = google_sql_database_instance.postgres.name
}

ephemeral "random_password" "database" {
  length  = 32
  special = false
}

resource "google_sql_user" "backend" {
  project             = var.project_id
  name                = "traceon"
  instance            = google_sql_database_instance.postgres.name
  password_wo         = ephemeral.random_password.database.result
  password_wo_version = 1
}

resource "google_secret_manager_secret" "database_url" {
  project   = var.project_id
  secret_id = "traceon-database-url"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret                 = google_secret_manager_secret.database_url.id
  secret_data_wo         = "postgresql+psycopg://${google_sql_user.backend.name}:${ephemeral.random_password.database.result}@/${google_sql_database.app.name}?host=/cloudsql/${google_sql_database_instance.postgres.connection_name}"
  secret_data_wo_version = 1
}

resource "google_secret_manager_secret_iam_member" "backend_database_url" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_project_iam_member" "backend_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.backend.email}"
}

resource "google_kms_key_ring" "traceon" {
  project    = var.project_id
  name       = "traceon-signing"
  location   = var.region
  depends_on = [google_project_service.kms]
}

resource "google_kms_crypto_key" "signing" {
  name            = "traceon-dsse"
  key_ring        = google_kms_key_ring.traceon.id
  purpose         = "ASYMMETRIC_SIGN"
  deletion_policy = "PREVENT"

  version_template {
    algorithm        = "RSA_SIGN_PSS_2048_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_version" "signing" {
  crypto_key      = google_kms_crypto_key.signing.id
  deletion_policy = "PREVENT"
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

resource "google_kms_crypto_key_iam_member" "backend_signer" {
  crypto_key_id = google_kms_crypto_key.signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.backend.email}"
}
