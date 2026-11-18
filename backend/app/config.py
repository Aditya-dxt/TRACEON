"""Runtime configuration for the Traceon API."""

import os


def cors_origins() -> list[str]:
    """Read allowed frontend origins; localhost is the development default."""

    configured = os.getenv("TRACEON_CORS_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]
