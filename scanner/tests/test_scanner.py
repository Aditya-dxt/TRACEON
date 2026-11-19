"""
scanner/tests/test_scanner.py

Unit and contract regression tests for Traceon Scanner.
"""

import json
import pytest
from pathlib import Path
import jsonschema

from scanner import scan_artifact, scan_dataset, generate_bom
from scanner.explain import ModelCardExplainer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = REPO_ROOT / "scanner" / "corpus"
CONTRACTS_DIR = REPO_ROOT / "contracts"


@pytest.fixture(scope="session")
def scan_result_schema():
    schema_path = CONTRACTS_DIR / "scan_result.schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def finding_schema():
    schema_path = CONTRACTS_DIR / "finding.schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def validator(scan_result_schema, finding_schema):
    import referencing
    finding_resource = referencing.Resource.from_contents(finding_schema)
    registry = (
        referencing.Registry()
        .with_resource("finding.schema.json", finding_resource)
        .with_resource("https://traceon.dev/contracts/finding.schema.json", finding_resource)
    )
    return jsonschema.Draft202012Validator(scan_result_schema, registry=registry)


def test_evil_pickle_detected(validator):
    evil_path = CORPUS_DIR / "evil.bin"
    assert evil_path.exists(), "Corpus file evil.bin must exist"

    result = scan_artifact(str(evil_path))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "pickle"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("pickle_opcode") == "fail"

    # Must contain critical finding for posix.system
    critical_findings = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(critical_findings) >= 1
    f = critical_findings[0]
    assert f["check"] == "pickle_opcode"
    assert f["category"] == "serialization"
    assert f["deterministic"] is True
    assert f["confidence"] == "high"
    assert f["evidence"]["module"] == "posix"
    assert f["evidence"]["callable"] == "system"
    assert "offset" in f["evidence"]


def test_clean_pickle_passes(validator):
    clean_path = CORPUS_DIR / "clean.pkl"
    assert clean_path.exists()

    result = scan_artifact(str(clean_path))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "pickle"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("pickle_opcode") == "pass"

    # Must have no findings above informational
    unacceptable_findings = [f for f in result["findings"] if f["severity"] not in ("informational",)]
    assert len(unacceptable_findings) == 0


def test_valid_safetensors_passes(validator):
    valid_path = CORPUS_DIR / "valid.safetensors"
    assert valid_path.exists()

    result = scan_artifact(str(valid_path))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "safetensors"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("safetensors_verify") == "pass"
    assert check_statuses.get("weight_stats") == "pass"

    critical_or_high = [f for f in result["findings"] if f["severity"] in ("critical", "high")]
    assert len(critical_or_high) == 0


def test_malformed_safetensors_fails(validator):
    malformed_path = CORPUS_DIR / "malformed.safetensors"
    assert malformed_path.exists()

    result = scan_artifact(str(malformed_path))
    validator.validate(instance=result)

    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("safetensors_verify") == "fail"

    critical_findings = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(critical_findings) >= 1
    assert "offset" in critical_findings[0]["title"].lower() or "offset" in critical_findings[0]["evidence"]


def test_dataset_unexpected_script_flagged(validator):
    ds_dir = CORPUS_DIR / "dataset_script"
    assert ds_dir.exists()

    result = scan_dataset(str(ds_dir))
    validator.validate(instance=result)

    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("dataset_guard") == "fail"

    script_findings = [f for f in result["findings"] if "unexpected_script.py" in f["title"] or "unexpected_script.py" in str(f["evidence"])]
    assert len(script_findings) >= 1
    assert script_findings[0]["category"] == "dataset"


def test_dataset_hash_mismatch_flagged(validator):
    ds_dir = CORPUS_DIR / "hash_mismatch"
    assert ds_dir.exists()

    result = scan_dataset(str(ds_dir))
    validator.validate(instance=result)

    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("dataset_guard") == "fail"

    mismatch_findings = [f for f in result["findings"] if "mismatch" in f["title"].lower()]
    assert len(mismatch_findings) >= 1


def test_bom_generation_cyclonedx_1_7():
    meta = {
        "name": "deep-finance-llm",
        "version": "1.2.0",
        "base_model": "mistralai/Mistral-7B-v0.1",
        "datasets": ["financial-qa-v1", "sec-filings-2026"],
        "packages": ["torch", "transformers", "accelerate"],
        "format": "safetensors",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }
    bom = generate_bom(meta, scan_results=[{"scan_id": "sc_test_123"}])

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.7"
    assert bom["metadata"]["component"]["name"] == "deep-finance-llm"
    
    # Verify properties namespace
    prop_names = [p["name"] for p in bom["metadata"]["component"]["properties"]]
    assert all(name.startswith("traceon:") for name in prop_names)
    assert "traceon:ext" in prop_names

    # Verify dependency links
    assert len(bom["dependencies"]) > 0
    assert len(bom["components"]) >= 3


def test_model_card_explainer_no_verdict():
    card_text = """---
license: apache-2.0
base_model: meta-llama/Llama-3-8B
datasets:
- squad
- natural_questions
---
# Llama-3-8B-FineTuned
This model was trained on QA datasets for enterprise support.
"""
    explainer = ModelCardExplainer()
    explanation = explainer.explain(card_text)

    assert explanation["type"] == "explanation"
    assert "verdict" not in explanation
    assert "severity" not in explanation
    assert explanation["data"]["licence"].lower() == "apache-2.0"
    assert explanation["data"]["base_model"] == "meta-llama/Llama-3-8B"


def test_scanner_non_raising_on_nonexistent_or_bad_path():
    # Never raise on bad input
    result = scan_artifact("non_existent_file_path_12345.bin")
    assert result["artifact"]["detected_format"] == "unknown"
    assert len(result["findings"]) >= 1

    ds_result = scan_dataset("non_existent_dir_path_12345")
    assert len(ds_result["findings"]) >= 1


def test_pytorch_zip_evil_detected(validator):
    evil_pt = CORPUS_DIR / "pytorch_evil.pt"
    assert evil_pt.exists()

    result = scan_artifact(str(evil_pt))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "pytorch_zip"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("pickle_opcode") == "fail"

    critical_findings = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(critical_findings) >= 1
    assert critical_findings[0]["evidence"]["module"] == "posix"
    assert critical_findings[0]["evidence"]["callable"] == "system"


def test_pytorch_zip_clean_passes(validator):
    clean_pt = CORPUS_DIR / "pytorch_clean.pt"
    assert clean_pt.exists()

    result = scan_artifact(str(clean_pt))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "pytorch_zip"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("pickle_opcode") == "pass"

    critical_or_high = [f for f in result["findings"] if f["severity"] in ("critical", "high")]
    assert len(critical_or_high) == 0


def test_dataset_guard_parquet_and_jsonl(tmp_path, validator):
    test_ds = tmp_path / "extended_ds"
    test_ds.mkdir()

    # 1. Spoofed Parquet (ends with .parquet but has invalid magic)
    bad_parquet = test_ds / "corrupt.parquet"
    bad_parquet.write_bytes(b"NOT_PARQUET_MAGIC_BYTES_1234")

    # 2. Corrupt JSONL
    bad_jsonl = test_ds / "data.jsonl"
    bad_jsonl.write_text('{"id": 1, "prompt": "hi"}\n{malformed json line}\n', encoding="utf-8")

    result = scan_dataset(str(test_ds))
    validator.validate(instance=result)

    findings = result["findings"]
    titles = [f["title"] for f in findings]
    assert any("Parquet" in t for t in titles)
    assert any("JSONL" in t for t in titles)


def test_weight_diff_against_base(tmp_path, validator):
    import struct
    # Create base safetensors
    base_file = tmp_path / "base.safetensors"
    base_raw = struct.pack("<4f", 1.0, 1.0, 1.0, 1.0)
    base_hdr = json.dumps({"weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}).encode("utf-8")
    with open(base_file, "wb") as f:
        f.write(struct.pack("<Q", len(base_hdr)))
        f.write(base_hdr)
        f.write(base_raw)

    # Create target safetensors with an unexpected extra layer
    target_file = tmp_path / "target.safetensors"
    target_raw = struct.pack("<8f", 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0)
    target_hdr = json.dumps({
        "weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        "unexpected_extra_layer": {"dtype": "F32", "shape": [2, 2], "data_offsets": [16, 32]}
    }).encode("utf-8")
    with open(target_file, "wb") as f:
        f.write(struct.pack("<Q", len(target_hdr)))
        f.write(target_hdr)
        f.write(target_raw)

    result = scan_artifact(str(target_file), base_model_path=str(base_file))
    validator.validate(instance=result)

    diff_findings = [f for f in result["findings"] if "unexpected_extra_layer" in str(f.get("evidence", {}))]
    assert len(diff_findings) >= 1
    assert diff_findings[0]["deterministic"] is False
    assert diff_findings[0]["severity"] != "critical"


def test_gguf_clean_passes(validator):
    clean_gguf = CORPUS_DIR / "clean.gguf"
    assert clean_gguf.exists()

    result = scan_artifact(str(clean_gguf))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "gguf"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("gguf_verify") == "pass"

    crit_or_high = [f for f in result["findings"] if f["severity"] in ("critical", "high")]
    assert len(crit_or_high) == 0


def test_gguf_malformed_fails(validator):
    malformed_gguf = CORPUS_DIR / "malformed.gguf"
    assert malformed_gguf.exists()

    result = scan_artifact(str(malformed_gguf))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "gguf"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("gguf_verify") == "fail"

    crit = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(crit) >= 1


def test_onnx_traversal_fails(validator):
    traversal_onnx = CORPUS_DIR / "traversal.onnx"
    assert traversal_onnx.exists()

    result = scan_artifact(str(traversal_onnx))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "onnx"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("onnx_verify") == "fail"

    crit = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(crit) >= 1
    assert "CWE-22" in crit[0]["evidence"]["cwe"]
    assert "AML.T0011" in crit[0]["evidence"]["mitre_atlas"]


def test_onnx_clean_passes(validator):
    clean_onnx = CORPUS_DIR / "clean.onnx"
    assert clean_onnx.exists()

    result = scan_artifact(str(clean_onnx))
    validator.validate(instance=result)

    assert result["artifact"]["detected_format"] == "onnx"
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("onnx_verify") == "pass"

    crit_or_high = [f for f in result["findings"] if f["severity"] in ("critical", "high")]
    assert len(crit_or_high) == 0


def test_threat_intel_mitre_atlas_and_cwe_enriched(validator):
    evil_path = CORPUS_DIR / "evil.bin"
    result = scan_artifact(str(evil_path))
    validator.validate(instance=result)

    findings = result["findings"]
    assert len(findings) >= 1
    f = findings[0]
    assert "mitre_atlas" in f["evidence"]
    assert "AML.T0011" in f["evidence"]["mitre_atlas"]
    assert "cwe" in f["evidence"]
    assert "CWE-78" in f["evidence"]["cwe"]


