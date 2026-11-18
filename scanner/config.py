"""
scanner/config.py

Configuration settings, resource limits, allow-lists, and deny-lists for the Traceon scanner.
"""

from typing import Set

# Resource Limits
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024 * 1024  # 50 GB default
MAX_HEADER_SIZE_BYTES = 100 * 1024 * 1024       # 100 MB max for safetensors header
MAX_PICKLE_NESTING_DEPTH = 15                   # Maximum recursion/nesting depth
SCAN_TIMEOUT_SECONDS = 180                      # 3 minutes max per scan step

# Pickle Scanner Deny-List (Modules and functions known to facilitate arbitrary code execution)
DENY_LISTED_MODULES: Set[str] = {
    "posix",
    "nt",
    "os",
    "subprocess",
    "sys",
    "shutil",
    "socket",
    "pty",
    "commands",
    "builtins",
    "builtin",
    "__builtin__",
    "importlib",
    "pip",
    "requests",
    "urllib",
    "urllib.request",
    "http.client",
    "ftplib",
    "telnetlib",
    "ctypes",
    "winreg",
    "_winapi",
    "code",
    "codeop",
    "webbrowser",
}

DENY_LISTED_CALLABLES: Set[str] = {
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "fork",
    "exec",
    "execfile",
    "eval",
    "compile",
    "getattr",
    "call",
    "check_call",
    "check_output",
    "open",
    "load",
    "loads",
    "unlink",
    "remove",
    "rmdir",
}

# Safe Allow-List (Known benign tensor constructors and serialization helpers for ML models)
SAFE_ALLOWED_GLOBALS: Set[tuple[str, str]] = {
    # PyTorch internals
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch.storage", "_load_from_bytes"),
    ("torch", "FloatStorage"),
    ("torch", "HalfStorage"),
    ("torch", "BFloat16Storage"),
    ("torch", "IntStorage"),
    ("torch", "LongStorage"),
    ("torch", "ByteStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "ShortStorage"),
    ("torch", "BoolStorage"),
    ("torch", "Tensor"),
    ("torch", "Size"),
    ("torch.nn.modules.container", "Sequential"),
    ("torch.nn.modules.container", "ModuleList"),
    ("torch.nn.modules.container", "ParameterList"),
    
    # Collections and basic python structures
    ("collections", "OrderedDict"),
    ("builtins", "bytearray"),
    ("builtins", "set"),
    ("builtins", "frozenset"),
    
    # NumPy
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("numpy", "float32"),
    ("numpy", "float64"),
    ("numpy", "int32"),
    ("numpy", "int64"),
}
