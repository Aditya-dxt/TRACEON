"""Cloud Run sandbox isolation checks; requires sandboxLauncher in the host."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def sandbox_cli() -> str | None:
    configured = os.getenv("TRACEON_SANDBOX_CLI")
    if configured:
        return configured if Path(configured).is_file() else None
    return shutil.which("sandbox") or (
        "/usr/local/gcp/bin/sandbox"
        if Path("/usr/local/gcp/bin/sandbox").is_file()
        else None
    )


def require_cloud_run_sandbox() -> str:
    cli = sandbox_cli()
    if cli is None:
        if os.getenv("TRACEON_REQUIRE_SANDBOX_TESTS") == "1":
            pytest.fail("sandboxLauncher is required for this isolation check")
        pytest.skip("Cloud Run sandbox CLI is not available in this environment")
    return cli


def test_sandbox_process_cannot_reach_the_public_internet():
    cli = require_cloud_run_sandbox()
    probe = (
        "import socket; "
        "s=socket.create_connection(('1.1.1.1', 443), timeout=3); "
        "s.close()"
    )
    result = subprocess.run(
        [cli, "do", "--", sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0, "sandbox unexpectedly established an internet connection"


def test_sandbox_root_filesystem_is_read_only():
    cli = require_cloud_run_sandbox()
    write_probe = "from pathlib import Path; Path('/traceon-read-only-probe').write_text('bad')"
    result = subprocess.run(
        [cli, "do", "--", sys.executable, "-c", write_probe],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0, "sandbox unexpectedly wrote to its root filesystem"
