"""Scanner subprocess entry point launched inside Cloud Run's sandbox."""

import json
import sys

from scanner import scan_artifact


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Expected one artifact path", "code": "INVALID_INPUT"}))
        return 2
    try:
        result = scan_artifact(sys.argv[1])
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception:
        # Scanner guarantees safe error reports for hostile files. This guard
        # keeps unexpected worker failures from leaking a traceback or path.
        print(json.dumps({"error": "Scanner execution failed", "code": "SCANNER_FAILED"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
