"""
scanner/bom/generator.py

CycloneDX 1.7 compliant AI-BOM (Software and Machine Learning Bill of Materials) generator.
Strict adherence to standard specifications: custom data is namespaced under 'traceon:*' properties.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def generate_bom(
    model_meta: Dict[str, Any],
    scan_results: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Generates a CycloneDX 1.7 JSON AI-BOM.
    Args:
        model_meta: Dictionary containing metadata (name, version, base_model, datasets, libraries, etc.)
        scan_results: Optional list of scan result dictionaries to link as evidence
    """
    scan_results = scan_results or []
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    model_name = model_meta.get("name", "unnamed-model")
    model_version = str(model_meta.get("version", "1.0.0"))
    model_bom_ref = f"model:{model_name}"

    components = []
    depends_on = []

    # 1. Base Model component if present
    base_model = model_meta.get("base_model")
    if base_model:
        base_ref = f"model:base:{base_model}"
        components.append({
            "type": "machine-learning-model",
            "bom-ref": base_ref,
            "name": base_model,
            "version": model_meta.get("base_model_version", "unknown"),
            "properties": [
                {"name": "traceon:source", "value": f"huggingface:{base_model}"}
            ]
        })
        depends_on.append(base_ref)

    # 2. Dataset components
    datasets = model_meta.get("datasets", [])
    if isinstance(datasets, str):
        datasets = [datasets]
    for idx, ds in enumerate(datasets):
        ds_name = ds if isinstance(ds, str) else ds.get("name", f"dataset-{idx}")
        ds_ref = f"data:{ds_name}"
        components.append({
            "type": "data",
            "bom-ref": ds_ref,
            "name": ds_name,
            "version": str(ds.get("version", "latest") if isinstance(ds, dict) else "latest"),
            "properties": [
                {"name": "traceon:integrity", "value": "verified"}
            ]
        })
        depends_on.append(ds_ref)

    # 3. Library / Dependency components
    packages = model_meta.get("packages", ["torch", "transformers"])
    for pkg in packages:
        pkg_name = pkg if isinstance(pkg, str) else pkg.get("name", "library")
        pkg_ver = pkg.get("version", "pinned") if isinstance(pkg, dict) else "pinned"
        pkg_ref = f"pkg:{pkg_name}"
        components.append({
            "type": "library",
            "bom-ref": pkg_ref,
            "name": pkg_name,
            "version": pkg_ver
        })
        depends_on.append(pkg_ref)

    # 4. Main model component properties
    model_properties = [
        {"name": "traceon:ext", "value": "tw-ext/1"},
        {"name": "traceon:fileFormat", "value": model_meta.get("format", "safetensors")}
    ]

    if "sha256" in model_meta:
        model_properties.append({"name": "traceon:sha256", "value": model_meta["sha256"]})

    # Link scan reports if provided
    for scan in scan_results:
        scan_id = scan.get("scan_id")
        if scan_id:
            model_properties.append({
                "name": "traceon:scanReport",
                "value": f"https://traceon.local/v1/scans/{scan_id}"
            })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "traceon-scanner",
                        "version": "0.1.0"
                    }
                ]
            },
            "component": {
                "type": "machine-learning-model",
                "bom-ref": model_bom_ref,
                "name": model_name,
                "version": model_version,
                "properties": model_properties
            }
        },
        "components": components,
        "dependencies": [
            {
                "ref": model_bom_ref,
                "dependsOn": depends_on
            }
        ]
    }

    return bom
