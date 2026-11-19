"""
scanner/cli.py

Command-line interface for the Traceon scanner.
Outputs valid JSON to stdout to seamlessly interface with backend workers and CI pipelines.

Usage:
  python -m scanner.cli scan --file <path>
  python -m scanner.cli dataset --dir <path>
  python -m scanner.cli bom --meta meta.json --scans scans.json
"""

import sys
import json
import argparse
from pathlib import Path

from scanner import scan_artifact, scan_dataset, generate_bom


def main():
    parser = argparse.ArgumentParser(
        prog="traceon-scanner",
        description="Traceon AI Supply Chain Security Scanner"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a model artifact file")
    scan_parser.add_argument("--file", required=True, help="Path to model file to scan")
    scan_parser.add_argument("--base-model", required=False, default=None, help="Optional path to base model for weight diffing")

    # Command: dataset
    dataset_parser = subparsers.add_parser("dataset", help="Scan a dataset directory")
    dataset_parser.add_argument("--dir", required=True, help="Path to dataset directory")

    # Command: bom
    bom_parser = subparsers.add_parser("bom", help="Generate CycloneDX 1.7 AI-BOM")
    bom_parser.add_argument("--meta", required=True, help="Path to model metadata JSON file")
    bom_parser.add_argument("--scans", required=False, default=None, help="Path to scan results JSON file")

    args = parser.parse_args()

    if args.command == "scan":
        result = scan_artifact(args.file, base_model_path=args.base_model)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    elif args.command == "dataset":
        result = scan_dataset(args.dir)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    elif args.command == "bom":
        try:
            with open(args.meta, "r", encoding="utf-8") as f:
                meta = json.load(f)
            scans = []
            if args.scans and Path(args.scans).exists():
                with open(args.scans, "r", encoding="utf-8") as f:
                    scans_data = json.load(f)
                    scans = scans_data if isinstance(scans_data, list) else [scans_data]
            bom_result = generate_bom(meta, scans)
            print(json.dumps(bom_result, indent=2))
            sys.exit(0)
        except Exception as e:
            err = {"error": f"Failed to generate BOM: {str(e)}", "code": "BOM_GEN_FAILED"}
            print(json.dumps(err, indent=2), file=sys.stderr)
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
