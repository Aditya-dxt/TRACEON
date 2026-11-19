"""
make_corpus.py

Generates harmless, controlled, synthetic test artifacts for Traceon scanner.
No real malware or dangerous exploits. All artifacts are tiny and synthetic.
"""

import os
import json
import struct
import pickle
import hashlib
from pathlib import Path


class EvilMarkerPayload:
    """A harmless dummy object that references os.system to test opcode detection."""
    def __reduce__(self):
        # Harmless marker command - never actually executed in our scanner!
        return (eval, ("'__traceon_harmless_marker_test__'",))


def create_pickle_with_import(module: str, func: str, arg: str) -> bytes:
    """Manually construct pickle bytecode importing a deny-listed module/callable."""
    # Protocol 2 pickle bytecode importing module.func(arg)
    # \x80\x02 : PROTO 2
    # c<module>\n<func>\n : GLOBAL
    # X<len><arg> : BINUNICODE
    # \x85 : TUPLE1
    # R : REDUCE
    # . : STOP
    b_mod = module.encode("ascii")
    b_func = func.encode("ascii")
    b_arg = arg.encode("utf-8")
    payload = (
        b"\x80\x02"
        + b"c" + b_mod + b"\n" + b_func + b"\n"
        + b"X" + struct.pack("<I", len(b_arg)) + b_arg
        + b"\x85"
        + b"R"
        + b"."
    )
    return payload


def make_corpus(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. evil.bin: Harmless pickle referencing posix.system
    evil_path = output_dir / "evil.bin"
    evil_bytes = create_pickle_with_import("posix", "system", "echo marker > /tmp/marker.txt")
    evil_path.write_bytes(evil_bytes)
    print(f"Created {evil_path} ({len(evil_bytes)} bytes)")

    # 2. clean.pkl: Clean pickle containing only safe python primitives
    clean_path = output_dir / "clean.pkl"
    clean_data = {
        "architecture": "Transformer",
        "num_layers": 4,
        "hidden_size": 128,
        "vocab_size": 5000,
        "hyperparameters": {
            "learning_rate": 0.0001,
            "batch_size": 32
        }
    }
    with open(clean_path, "wb") as f:
        pickle.dump(clean_data, f, protocol=4)
    print(f"Created {clean_path} ({clean_path.stat().st_size} bytes)")

    # 3. valid.safetensors: Valid tiny Safetensors file
    # Safetensors layout:
    # 8 bytes: Header size N (little-endian unsigned 64-bit int)
    # N bytes: JSON header string
    # Remaining: Tensor binary buffers
    valid_st_path = output_dir / "valid.safetensors"
    # 2x2 float32 matrix = 4 floats = 16 bytes
    raw_tensor = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
    header_obj = {
        "weight": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, len(raw_tensor)]
        },
        "__metadata__": {
            "format": "pt",
            "framework": "traceon-test"
        }
    }
    header_bytes = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    header_len = len(header_bytes)
    with open(valid_st_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_bytes)
        f.write(raw_tensor)
    print(f"Created {valid_st_path} ({valid_st_path.stat().st_size} bytes)")

    # 4. malformed.safetensors: Offset declared exceeds file size
    malformed_st_path = output_dir / "malformed.safetensors"
    malformed_header = {
        "weight": {
            "dtype": "F32",
            "shape": [2, 2],
            # Offset points to 100,000 bytes, well past the end of the file!
            "data_offsets": [0, 100000]
        }
    }
    m_header_bytes = json.dumps(malformed_header, separators=(",", ":")).encode("utf-8")
    m_header_len = len(m_header_bytes)
    with open(malformed_st_path, "wb") as f:
        f.write(struct.pack("<Q", m_header_len))
        f.write(m_header_bytes)
        f.write(raw_tensor)  # only 16 bytes written
    print(f"Created {malformed_st_path} ({malformed_st_path.stat().st_size} bytes)")

    # 5. dataset_script/: Dataset folder with unexpected python script
    ds_dir = output_dir / "dataset_script"
    ds_dir.mkdir(exist_ok=True)
    (ds_dir / "train.csv").write_text("id,text,label\n1,hello world,0\n2,test sample,1\n", encoding="utf-8")
    (ds_dir / "unexpected_script.py").write_text(
        "# Unexpected executable script inside dataset folder\n"
        "import sys\nprint('This should be flagged by dataset guard')\n",
        encoding="utf-8"
    )
    print(f"Created dataset directory: {ds_dir}")

    # 6. hash_mismatch/: Dataset directory with manifest hash mismatch
    mismatch_dir = output_dir / "hash_mismatch"
    mismatch_dir.mkdir(exist_ok=True)
    sample_content = "genuine dataset content"
    (mismatch_dir / "data.json").write_text(json.dumps({"records": [1, 2, 3]}), encoding="utf-8")
    manifest = {
        "files": {
            "data.json": {
                # Tampered or incorrect sha256
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "size_bytes": 100
            }
        }
    }
    (mismatch_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Created hash mismatch directory: {mismatch_dir}")

    # 7. pytorch_clean.pt: Synthetic PyTorch ZIP checkpoint (benign)
    import zipfile
    clean_pt_path = output_dir / "pytorch_clean.pt"
    with zipfile.ZipFile(clean_pt_path, "w") as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/byteorder", "little\n")
        # Safe serialized dict inside data.pkl
        clean_pkl_bytes = pickle.dumps({"layer1.weight": [1.0, 2.0], "layer1.bias": [0.1]}, protocol=4)
        zf.writestr("archive/data.pkl", clean_pkl_bytes)
    print(f"Created {clean_pt_path} ({clean_pt_path.stat().st_size} bytes)")

    # 8. pytorch_evil.pt: Synthetic PyTorch ZIP checkpoint containing nested malicious pickle
    evil_pt_path = output_dir / "pytorch_evil.pt"
    with zipfile.ZipFile(evil_pt_path, "w") as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/byteorder", "little\n")
        # Malicious payload in data.pkl
        evil_pkl_bytes = create_pickle_with_import("posix", "system", "whoami")
        zf.writestr("archive/data.pkl", evil_pkl_bytes)
    print(f"Created {evil_pt_path} ({evil_pt_path.stat().st_size} bytes)")

    # 9. clean.gguf: Synthetic valid GGUF model
    clean_gguf = output_dir / "clean.gguf"
    with open(clean_gguf, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version 3
        f.write(struct.pack("<Q", 1))  # tensor_count = 1
        f.write(struct.pack("<Q", 1))  # metadata_kv_count = 1
        # KV: key = "general.architecture", type = string (8), value = "llama"
        k_name = b"general.architecture"
        f.write(struct.pack("<Q", len(k_name)))
        f.write(k_name)
        f.write(struct.pack("<I", 8))  # string type
        val_name = b"llama"
        f.write(struct.pack("<Q", len(val_name)))
        f.write(val_name)
    print(f"Created {clean_gguf} ({clean_gguf.stat().st_size} bytes)")

    # 10. malformed.gguf: Truncated GGUF header
    malformed_gguf = output_dir / "malformed.gguf"
    malformed_gguf.write_bytes(b"GGUF\x03\x00\x00\x00")  # truncated
    print(f"Created {malformed_gguf} ({malformed_gguf.stat().st_size} bytes)")

    # 11. clean.onnx: Minimal valid ONNX model structure
    clean_onnx = output_dir / "clean.onnx"
    # Tag 1 (ir_version): varint 7 (\x08\x07)
    # Tag 2 (producer_name): string 'onnx' (\x12\x04onnx)
    clean_onnx.write_bytes(b"\x08\x07\x12\x04onnx\x1a\x07test_graph")
    print(f"Created {clean_onnx} ({clean_onnx.stat().st_size} bytes)")

    # 12. traversal.onnx: Malicious ONNX with external path traversal
    traversal_onnx = output_dir / "traversal.onnx"
    # Contains 'location' followed by path traversal string '../../../../etc/shadow'
    traversal_onnx.write_bytes(b"\x08\x07\x12\x04onnxlocation../../../../etc/shadow")
    print(f"Created {traversal_onnx} ({traversal_onnx.stat().st_size} bytes)")


if __name__ == "__main__":
    current_dir = Path(__file__).resolve().parent
    make_corpus(current_dir)
