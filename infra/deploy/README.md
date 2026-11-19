# Traceon deployment templates

The staging Terraform stack in `storage/` creates the Cloud SQL PostgreSQL instance, database, generated SQL user, and `traceon-database-url` Secret Manager secret. It also grants the backend service account Cloud SQL Client and secret access, and creates the Artifact Registry repository. Apply only after reviewing and approving its saved plan.

Build the API image from the repository root with `docker build -f backend/Dockerfile -t REGION-docker.pkg.dev/PROJECT_ID/traceon/backend:RELEASE .`. Push it to Artifact Registry, then replace the uppercase placeholders in `backend-service.yaml` and deploy it. Set the `run.googleapis.com/cloudsql-instances` annotation to the Terraform `database_instance_connection_name` output. Do not put database credentials in YAML or commit Terraform state, plan files, or `terraform.tfvars`. The Dockerfile-specific ignore file excludes local database/quarantine data and non-runtime files from the build context.

Deploy the scanner worker with the service template in `infra/sandbox/service.yaml`. The API uses its dedicated backend service account and invokes the worker with a Google-issued ID token. Grant that backend service account `roles/run.invoker` on the worker service after deployment. The worker remains internal; its sandbox child process has no bucket credentials.

Apply the storage and signing IAM configuration in `infra/deploy/storage/` first. Then set the bucket, KMS key version, worker URL, database secret, and frontend origin in the API service template. Database migrations are a separate release step: run `alembic -c backend/alembic.ini upgrade head` with the same `TRACEON_DATABASE_URL` secret before shifting production traffic.

`infra/loadtest/` contains a low-impact health endpoint smoke-load scenario. Run it against staging and record results before testing scan throughput or production scale.
