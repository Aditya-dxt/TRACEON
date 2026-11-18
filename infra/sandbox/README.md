# Isolated scanner worker

The internal Cloud Run service downloads only objects from its configured quarantine bucket, writes each artifact to a short-lived local file, and runs the scanner using the Cloud Run sandbox CLI. The sandbox process is started without `--allow-egress`; its default network policy blocks outbound connections, and its default root filesystem is read-only. The scanner process does not receive the host service's environment variables or credentials.

The Cloud Run service uses an internal ingress policy and a dedicated service account. Grant that account `roles/storage.objectViewer` on the quarantine bucket only. Do not grant the sandbox process Storage access; the host worker fetches the object before launching the isolated process.

## Build and deploy

Build the image from the repository root so the Docker build can copy `scanner/`:

```powershell
docker build -f infra/sandbox/Dockerfile -t REGION-docker.pkg.dev/PROJECT_ID/traceon/traceon-sandbox:latest .
docker push REGION-docker.pkg.dev/PROJECT_ID/traceon/traceon-sandbox:latest
```

Before applying `service.yaml`, replace `PROJECT_ID`, `REGION`, the image location, the dedicated service account, and `QUARANTINE_BUCKET_NAME`. Enable the Cloud Run sandbox launcher and second-generation environment from the service configuration. Cloud Run sandboxes are currently a Preview feature.

## Isolation checks

The automated checks in `tests/test_sandbox_network.py` attempt a public TCP connection and a root-filesystem write from inside the sandbox. Run them on a Cloud Run service revision with `sandboxLauncher: true`:

```powershell
$env:TRACEON_REQUIRE_SANDBOX_TESTS = "1"
python -m pytest infra/sandbox/tests -q
```

When the sandbox CLI is unavailable, those Cloud Run isolation checks skip unless `TRACEON_REQUIRE_SANDBOX_TESTS=1` is set.
