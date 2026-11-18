# Traceon Cloud Storage

This Terraform configuration creates separate private buckets for quarantine and evidence, enables object versioning, and creates dedicated backend and sandbox service identities. The backend can read and create objects in both buckets. The isolated scanner host can read quarantine objects only. Neither identity receives bucket-scoped delete access.

Buckets use uniform bucket-level access and enforced public access prevention. `force_destroy` is disabled so Terraform will not empty stored artifacts or evidence during deletion.

## Apply

Copy `terraform.tfvars.example` to `terraform.tfvars` and set the project, service region, and bucket location. Authenticate Terraform using Application Default Credentials; do not create or commit service-account key files.

```powershell
terraform init
terraform plan -out traceon-storage.tfplan
terraform apply traceon-storage.tfplan
```

The plan shows the exact buckets, service identities, and bucket-scoped grants before creation. Apply requires permission to enable project APIs, create service accounts and buckets, and grant bucket IAM roles.

After apply, set `TRACEON_QUARANTINE_BUCKET` on the sandbox worker to the `quarantine_bucket_name` output. Use `evidence_bucket_name` for backend evidence storage. Set the Cloud Run service identity to `sandbox_service_account_email`; run the API as `backend_service_account_email`.
