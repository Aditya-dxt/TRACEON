# Traceon staging infrastructure

This Terraform stack prepares the Traceon staging foundation in one reviewable plan:

- Private, versioned quarantine and evidence buckets with public access prevention and bucket-scoped IAM.
- Dedicated backend and sandbox service accounts, plus a non-exportable Cloud KMS signing key.
- A single-zone Cloud SQL for PostgreSQL 16 instance, database, and generated database user.
- A Secret Manager secret containing the PostgreSQL SQLAlchemy URL, accessible to the backend service account only.
- An Artifact Registry Docker repository and the Cloud Run, Cloud SQL, Secret Manager, Artifact Registry, Storage, IAM, and KMS APIs.

The database defaults to `db-f1-micro`, a shared-core development tier without a Cloud SQL SLA. It uses 10 GiB HDD storage, has backups disabled, and has deletion protection enabled. Cloud SQL runs continuously and is billed while it is on; the tier, region, storage, and network use affect the bill. The plan is not a price estimate. Review current regional pricing before applying.

The Terraform configuration creates the database password ephemerally and uses write-only provider arguments for both the SQL user and Secret Manager version. The password and connection URL are therefore not saved in the Terraform plan or state. Still keep the local plan and state files private, and never commit them. `.gitignore` excludes Terraform state, plans, and `terraform.tfvars`.

## Plan and apply

Copy `terraform.tfvars.example` to `terraform.tfvars` and set the project, region, and bucket location. For this staging environment, use `traceon-515204`, `asia-south1`, and `asia-south1`. Authenticate Terraform with Google Application Default Credentials; do not create service-account key files.

```powershell
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -out traceon-staging.tfplan
terraform show -no-color traceon-staging.tfplan
```

Review every resource in the plan and the current Cloud SQL regional price before applying. Applying creates billable cloud resources. Do not run `terraform apply` until the plan has been reviewed and the project owner approves it.

After approval and apply, use the outputs for the Cloud Run API service. The API service account receives `roles/cloudsql.client` and access to `traceon-database-url`; the generated URL uses the Cloud Run `/cloudsql/PROJECT:REGION:INSTANCE` socket. The backend service template's `run.googleapis.com/cloudsql-instances` annotation must be filled with the `database_instance_connection_name` output. Replace its other project, region, image, worker URL, and frontend-origin placeholders before deployment.

The sandbox host can read quarantine objects only. It has no access to the database secret or KMS signing key. Neither service account receives bucket-scoped delete access.
