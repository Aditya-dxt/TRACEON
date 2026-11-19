"""
scanner/threat_intel/rules.py

Threat Intelligence and Exploitation Signature Database for Traceon Scanner.
Maps dangerous serialization callables, memory corruption patterns, and supply-chain threats
to official MITRE ATLAS, MITRE ATT&CK, and CWE taxonomy identifiers.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Set


@dataclass(frozen=True)
class ThreatSignature:
    category: str
    severity: str
    title: str
    mitre_atlas: str
    cwe: str
    att_and_ck: str
    description: str
    recommendation: str


# Threat Categories:
# - code_execution: Arbitrary shell or process execution
# - file_manipulation: Arbitrary disk read/write/delete
# - network_exfiltration: Socket/HTTP communication
# - memory_injection: Native library loading, pointer manipulation
# - code_injection: Dynamic evaluation or reflection
# - framework_exploit: Machine learning framework-specific serialization bypasses

GADGET_SIGNATURES: Dict[Tuple[str, str], ThreatSignature] = {
    # 1. OS Command & Process Execution
    ("posix", "system"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="POSIX Shell Command Execution",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Invokes posix.system to execute arbitrary host shell commands.",
        recommendation="Do not load this file. Checkpoint contains direct host shell execution."
    ),
    ("nt", "system"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Windows NT Command Execution",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Invokes nt.system to execute arbitrary Windows command prompt instructions.",
        recommendation="Do not load this file. Checkpoint contains direct host shell execution."
    ),
    ("os", "system"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Operating System Command Execution",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Invokes os.system to spawn shell commands during deserialization.",
        recommendation="Do not load this file. Checkpoint contains arbitrary code execution."
    ),
    ("os", "popen"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Piped Process Execution",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Opens a pipe to or from a command using os.popen.",
        recommendation="Reject file. Model file should contain weights, not pipeline execution."
    ),
    ("subprocess", "Popen"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Subprocess Process Creation",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Launches external processes via subprocess.Popen.",
        recommendation="Do not load. Potential backdoor or reverse shell initiation."
    ),
    ("subprocess", "call"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Synchronous Subprocess Call",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Executes a system command and waits for return value via subprocess.call.",
        recommendation="Do not load this file."
    ),
    ("subprocess", "check_output"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Subprocess Output Capture",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Runs command with arguments and returns its output.",
        recommendation="Do not load this file."
    ),
    ("pty", "spawn"): ThreatSignature(
        category="code_execution",
        severity="critical",
        title="Interactive Pseudo-Terminal Spawn",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-78 (OS Command Injection)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Spawns an interactive shell session via pseudo-terminal.",
        recommendation="Reject immediately: classic reverse shell payload signature."
    ),

    # 2. Dynamic Code Injection & Compilation
    ("builtins", "eval"): ThreatSignature(
        category="code_injection",
        severity="critical",
        title="Dynamic Python Expression Evaluation",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-94 (Improper Control of Generation of Code)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Executes dynamically passed Python expressions via eval().",
        recommendation="Do not load. Arbitrary Python code can be evaluated during unpickling."
    ),
    ("builtins", "exec"): ThreatSignature(
        category="code_injection",
        severity="critical",
        title="Dynamic Python Code Execution",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-94 (Improper Control of Generation of Code)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Executes arbitrary Python code blocks via exec().",
        recommendation="Do not load. Deserialization allows arbitrary execution."
    ),
    ("builtins", "compile"): ThreatSignature(
        category="code_injection",
        severity="critical",
        title="Dynamic Bytecode Compilation",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-94 (Improper Control of Generation of Code)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Compiles dynamic source code strings into AST or code objects.",
        recommendation="Review why model requires dynamic runtime compilation."
    ),
    ("builtins", "__import__"): ThreatSignature(
        category="code_injection",
        severity="critical",
        title="Dynamic Module Import Invocation",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-94 (Improper Control of Generation of Code)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Calls __import__ to load arbitrary Python packages at runtime.",
        recommendation="Block: Dynamic module loading bypasses standard package manifests."
    ),
    ("importlib", "import_module"): ThreatSignature(
        category="code_injection",
        severity="critical",
        title="Importlib Dynamic Module Loader",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-94 (Improper Control of Generation of Code)",
        att_and_ck="T1059.006 (Python Command Interpreter)",
        description="Programmatically imports modules via importlib.",
        recommendation="Block unapproved dynamic module imports."
    ),

    # 3. File System Manipulation & Exfiltration
    ("builtins", "open"): ThreatSignature(
        category="file_manipulation",
        severity="high",
        title="Arbitrary File Access",
        mitre_atlas="AML.T0048 (Exfiltration via Artifact)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1005 (Data from Local System)",
        description="Invokes built-in open() to read or write local filesystem contents.",
        recommendation="Investigate why model file touches the host filesystem."
    ),
    ("os", "remove"): ThreatSignature(
        category="file_manipulation",
        severity="high",
        title="File Deletion Operation",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1070.004 (File Deletion)",
        description="Calls os.remove to delete files on the host.",
        recommendation="Block checkpoint containing destructive operations."
    ),
    ("shutil", "rmtree"): ThreatSignature(
        category="file_manipulation",
        severity="critical",
        title="Recursive Directory Deletion",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1070.004 (File Deletion)",
        description="Invokes shutil.rmtree to recursively wipe directories.",
        recommendation="Block destructive model file."
    ),

    # 4. Network Connections & C2
    ("socket", "socket"): ThreatSignature(
        category="network_exfiltration",
        severity="critical",
        title="Raw Network Socket Creation",
        mitre_atlas="AML.T0048 (Exfiltration via Artifact)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1041 (Exfiltration Over C2 Channel)",
        description="Instantiates raw network sockets during deserialization.",
        recommendation="Block file. AI models must never initiate outbound network connections."
    ),
    ("urllib.request", "urlopen"): ThreatSignature(
        category="network_exfiltration",
        severity="critical",
        title="HTTP Remote Network Request",
        mitre_atlas="AML.T0048 (Exfiltration via Artifact)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1071.001 (Web Protocols)",
        description="Fetches or exfiltrates data over HTTP/HTTPS during load time.",
        recommendation="Block file. Models must not download payloads or transmit credentials."
    ),
    ("requests", "get"): ThreatSignature(
        category="network_exfiltration",
        severity="critical",
        title="HTTP GET Request via Requests",
        mitre_atlas="AML.T0048 (Exfiltration via Artifact)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1071.001 (Web Protocols)",
        description="Makes outbound HTTP requests via requests.get.",
        recommendation="Block file. Model attempts external communication."
    ),
    ("requests", "post"): ThreatSignature(
        category="network_exfiltration",
        severity="critical",
        title="HTTP POST Request (Data Exfiltration)",
        mitre_atlas="AML.T0048 (Exfiltration via Artifact)",
        cwe="CWE-502 (Deserialization of Untrusted Data)",
        att_and_ck="T1041 (Exfiltration Over C2 Channel)",
        description="Posts local data to external endpoints via requests.post.",
        recommendation="Block file: High probability of data exfiltration attempt."
    ),

    # 5. Native Memory & DLL Injection
    ("ctypes", "CDLL"): ThreatSignature(
        category="memory_injection",
        severity="critical",
        title="Native Shared Library Loading (ctypes)",
        mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
        cwe="CWE-114 (Process Control)",
        att_and_ck="T1055 (Process Injection)",
        description="Loads compiled native libraries (.so / .dll) directly into memory.",
        recommendation="Block file: Native library loading can execute binary exploits."
    ),
}


def lookup_signature(module: str, callable_name: str) -> Optional[ThreatSignature]:
    """Look up an exact or module-level threat signature."""
    # 1. Exact match (module, callable)
    if (module, callable_name) in GADGET_SIGNATURES:
        return GADGET_SIGNATURES[(module, callable_name)]

    # 2. Check alias or builtins variants
    if module in ("__builtin__", "builtin"):
        return GADGET_SIGNATURES.get(("builtins", callable_name))

    # 3. Fallback for dangerous modules
    if module in ("posix", "nt", "subprocess", "socket", "ctypes"):
        return ThreatSignature(
            category="code_execution",
            severity="critical",
            title=f"Dangerous Function Call in {module}: {callable_name}",
            mitre_atlas="AML.T0011.000 (Unsafe AI Artifacts)",
            cwe="CWE-502 (Deserialization of Untrusted Data)",
            att_and_ck="T1059.006 (Python Command Interpreter)",
            description=f"Invokes {module}.{callable_name} during unpickling.",
            recommendation="Do not load this file. Request a Safetensors version."
        )

    return None
