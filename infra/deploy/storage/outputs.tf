output "quarantine_bucket_name" {
  description = "Private bucket for newly imported artifacts awaiting scans."
  value       = google_storage_bucket.quarantine.name
}

output "evidence_bucket_name" {
  description = "Private bucket for scanner outputs, BOMs, and attestations."
  value       = google_storage_bucket.evidence.name
}

output "backend_service_account_email" {
  description = "Attach this identity to the Traceon API Cloud Run service."
  value       = google_service_account.backend.email
}

output "sandbox_service_account_email" {
  description = "Attach this identity to the internal scanner host Cloud Run service."
  value       = google_service_account.sandbox.email
}

output "signing_key_version_name" {
  description = "Set TRACEON_KMS_KEY_VERSION to this asymmetric signing key version resource name."
  value       = google_kms_crypto_key_version.signing.name
}
