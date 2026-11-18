"""Verify a registered artifact digest against Traceon's signed attestation."""

import argparse
import json
import sys
from urllib.error import URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha256", help="64-character SHA-256 of the artifact")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Traceon API base URL")
    args = parser.parse_args()
    request = Request(
        f"{args.api_url.rstrip('/')}/v1/verify",
        data=json.dumps({"sha256": args.sha256}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read())
    except (URLError, TimeoutError, ValueError) as exc:
        print(f"Verification request failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("valid") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
