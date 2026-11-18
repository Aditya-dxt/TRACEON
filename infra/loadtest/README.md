# Traceon API smoke load test

This k6 scenario measures the API health endpoint without creating assets or scanner jobs. Run it against a non-production deployment first:

```powershell
$env:TRACEON_BASE_URL = "https://<traceon-api-url>"
$env:VUS = "2"
$env:DURATION = "30s"
k6 run infra/loadtest/health.js
```

Increase `VUS` and `DURATION` only after the small run passes and the service owner has approved a larger load. This does not claim scanner throughput or Cloud Run sandbox capacity; those require a representative artifact set and a project-specific test window.
