import {
  Asset,
  ScanResult,
  AttestationEnvelope,
  CycloneDXBOM,
  VerifyResult,
} from "../types/traceon";

export const MOCK_ASSETS: Asset[] = [
  {
    asset_id: "a_blocked_001",
    name: "malicious_checkpoint.bin",
    source: "huggingface:untrusted-user/financial-llm@rev-1",
    format: "pickle",
    size_bytes: 1024,
    sha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    latest_verdict: "BLOCK",
    latest_scan_id: "sc_001",
    attestation_id: null,
    created_at: "2026-11-20T10:00:00Z",
    verdict: {
      decision_id: "d_001",
      asset_id: "a_blocked_001",
      verdict: "BLOCK",
      reasons: [
        "f_001: critical, deterministic, high confidence (posix.system call detected in pickle bytecode)",
      ],
      policy_id: "default",
      policy_version: 1,
      decided_at: "2026-11-20T10:00:03Z",
    },
    findings_summary: {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    },
  },
  {
    asset_id: "a_quarantine_002",
    name: "experimental_weights.safetensors",
    source: "huggingface:community-lab/vision-backdoor-test@v2",
    format: "safetensors",
    size_bytes: 1048576,
    sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
    latest_verdict: "QUARANTINE",
    latest_scan_id: "sc_002",
    attestation_id: null,
    created_at: "2026-11-20T10:01:00Z",
    verdict: {
      decision_id: "d_002",
      asset_id: "a_quarantine_002",
      verdict: "QUARANTINE",
      reasons: [
        "f_002: high finding with medium confidence (weight anomaly detected in layer 4 vs base model)",
      ],
      policy_id: "default",
      policy_version: 1,
      decided_at: "2026-11-20T10:02:00Z",
    },
    findings_summary: {
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      informational: 0,
    },
  },
  {
    asset_id: "a_conditional_004",
    name: "dialogue-eval-adapter.safetensors",
    source: "huggingface:partner-org/dialogue-adapter@v1.2",
    format: "safetensors",
    size_bytes: 2097152,
    sha256: "a1c97efb199042b7899eec3d778841a027ecb819f3900138da0b1e326c2e39ba",
    latest_verdict: "CONDITIONAL",
    latest_scan_id: "sc_004",
    attestation_id: null,
    created_at: "2026-11-20T10:03:00Z",
    verdict: {
      decision_id: "d_004",
      asset_id: "a_conditional_004",
      verdict: "CONDITIONAL",
      reasons: [
        "f_004: low/medium finding: license unverified in model card. Ticket JIRA-SEC-492 created with 14-day expiry.",
      ],
      policy_id: "default",
      policy_version: 1,
      decided_at: "2026-11-20T10:04:00Z",
    },
    findings_summary: {
      critical: 0,
      high: 0,
      medium: 1,
      low: 1,
      informational: 1,
    },
  },
  {
    asset_id: "a_approved_003",
    name: "model.safetensors",
    source: "huggingface:google/gemma-2-2b@main",
    format: "safetensors",
    size_bytes: 4821034,
    sha256: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
    latest_verdict: "APPROVE",
    latest_scan_id: "sc_003",
    attestation_id: "att_003",
    created_at: "2026-11-20T10:05:00Z",
    verdict: {
      decision_id: "d_003",
      asset_id: "a_approved_003",
      verdict: "APPROVE",
      reasons: [
        "All checks passed cleanly with no findings above informational.",
      ],
      policy_id: "default",
      policy_version: 1,
      decided_at: "2026-11-20T10:05:03Z",
    },
    findings_summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 1,
    },
  },
];

export const MOCK_SCANS: Record<string, ScanResult> = {
  sc_001: {
    scan_id: "sc_001",
    engine_version: "0.1.0",
    artifact: {
      name: "evil_model.bin",
      size_bytes: 1024,
      sha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      detected_format: "pickle",
    },
    checks_run: [
      { name: "format_detect", status: "pass" },
      { name: "sha256_hash", status: "pass" },
      { name: "pickle_opcode", status: "fail" },
      { name: "safetensors_verify", status: "skipped" },
    ],
    findings: [
      {
        finding_id: "f_001",
        check: "pickle_opcode",
        category: "serialization",
        severity: "critical",
        confidence: "high",
        deterministic: true,
        title: "Deny-listed import in pickle",
        evidence: {
          module: "posix",
          callable: "system",
          offset: "0x0042",
          file: "evil_model.bin",
          sha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        },
        recommendation: "Do not load this file. Request a Safetensors version.",
        explanation:
          "Gemini Explanation: The disassembled pickle bytecode executes posix.system at byte offset 0x0042. This would grant arbitrary command execution upon deserialization.",
      },
    ],
    started_at: "2026-11-20T10:00:00Z",
    completed_at: "2026-11-20T10:00:01Z",
  },
  sc_002: {
    scan_id: "sc_002",
    engine_version: "0.1.0",
    artifact: {
      name: "experimental_weights.safetensors",
      size_bytes: 1048576,
      sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      detected_format: "safetensors",
    },
    checks_run: [
      { name: "format_detect", status: "pass" },
      { name: "sha256_hash", status: "pass" },
      { name: "safetensors_verify", status: "pass" },
      { name: "weight_stats", status: "warn" },
    ],
    findings: [
      {
        finding_id: "f_002",
        check: "weight_stats",
        category: "weights",
        severity: "high",
        confidence: "medium",
        deterministic: false,
        title: "Statistical weight anomaly in layer 4",
        evidence: {
          layer: "transformer.layer.4.attention.weight",
          norm_diff: 4.82,
          z_score: 3.91,
          threshold: 3.0,
          file: "experimental_weights.safetensors",
          sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
        },
        recommendation:
          "Quarantine model in staging. Perform activation backdoor probe before deployment.",
        explanation:
          "Gemini Explanation: Tensor distribution diverges from base architecture with high z-score anomaly, consistent with trigger backdoor perturbation.",
      },
    ],
    started_at: "2026-11-20T10:01:00Z",
    completed_at: "2026-11-20T10:01:03Z",
  },
  sc_003: {
    scan_id: "sc_003",
    engine_version: "0.1.0",
    artifact: {
      name: "model.safetensors",
      size_bytes: 4821034,
      sha256: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
      detected_format: "safetensors",
    },
    checks_run: [
      { name: "format_detect", status: "pass" },
      { name: "sha256_hash", status: "pass" },
      { name: "safetensors_verify", status: "pass" },
      { name: "weight_stats", status: "pass" },
    ],
    findings: [
      {
        finding_id: "f_info_001",
        check: "safetensors_verify",
        category: "serialization",
        severity: "informational",
        confidence: "high",
        deterministic: true,
        title: "Safetensors header verified clean",
        evidence: {
          header_size_bytes: 2048,
          tensors_count: 128,
          offsets_valid: true,
        },
        recommendation: "Safetensors structure is valid and non-executable.",
        explanation:
          "Gemini Explanation: Deserialization safety confirmed. No executable code constructs present.",
      },
    ],
    started_at: "2026-11-20T10:05:00Z",
    completed_at: "2026-11-20T10:05:02Z",
  },
};

export const MOCK_ATTESTATION: AttestationEnvelope = {
  payloadType: "application/vnd.in-toto+json",
  payload:
    "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoibW9kZWwuc2FmZXRlbnNvcnMiLCJkaWdlc3QiOnsic2hhMjU2IjoiNGI1ZDFhOGU5OWIyNGI4OWMzZTQxNGM3MThmYTY1ZjI0MmQ1ZjA3Mjk3OWZiNjNkY2Y4YjM5NDkzMWE3Yzg2YSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3RyYWNlb24uZXhhbXBsZS9wcmVkaWNhdGUvbW9kZWwtYXNzZXNzbWVudC92MSIsInByZWRpY2F0ZSI6eyJib21EaWdlc3QiOnsic2hhMjU2IjoiYzc5ZjhhZWE3ODFmZDUwNmI4OGU4ZDMyMTFhNWQzOGQ4YjJmYWRlNGYyYzA3MGEyOGI0N2ExZjA5NDNjMjQ2YSJ9LCJzY2FuSWQiOiJzY18wMDMiLCJlbmdpbmVWZXJzaW9uIjoiMC4xLjAiLCJwb2xpY3lJZCI6ImRlZmF1bHQiLCJwb2xpY3lWZXJzaW9uIjoxLCJ2ZXJkaWN0IjoiQVBQUk9WRSIsImlzc3VlZEF0IjoiMjAyNi0xMS0yMFQxMDowNTowMFoiLCJleHBpcmVzQXQiOiIyMDI3LTAyLTIwVDEwOjA1OjAwWiJ9fQ==",
  statement: {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: "model.safetensors",
        digest: {
          sha256: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
        },
      },
    ],
    predicateType: "https://traceon.example/predicate/model-assessment/v1",
    predicate: {
      bomDigest: {
        sha256: "c79f8aea781fd506b88e8d3211a5d38d8b2fade4f2c070a28b47a1f0943c246a",
      },
      scanId: "sc_003",
      engineVersion: "0.1.0",
      policyId: "default",
      policyVersion: 1,
      verdict: "APPROVE",
      issuedAt: "2026-11-20T10:05:00Z",
      expiresAt: "2027-02-20T10:05:00Z",
    },
  },
  signatures: [
    {
      keyid:
        "gcp-kms-projects/traceon-prod/locations/global/keyRings/attestation/cryptoKeys/signer/cryptoKeyVersions/1",
      sig: "MEQCIAx1P79yJ0fV5K0Y14iOqY2H8R0pG7vW1tZzZ8Y8d9cZAiB8qV4X8Y5k7l3M2N1O0P9Q8R7S6T5U4V3W2X1Y0Z9A==",
    },
  ],
};

export const MOCK_BOM: CycloneDXBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  version: 1,
  metadata: {
    timestamp: "2026-11-20T10:05:00Z",
    tools: {
      components: [
        {
          type: "application",
          name: "traceon",
          version: "0.1.0",
        },
      ],
    },
    component: {
      type: "machine-learning-model",
      "bom-ref": "model:bank-llm-7b-ft",
      name: "bank-llm-7b-ft",
      version: "rev-4",
    },
    properties: [
      {
        name: "traceon:ext",
        value: "tw-ext/1",
      },
    ],
  },
  components: [
    {
      type: "machine-learning-model",
      "bom-ref": "model:base",
      name: "example-org/llm-7b",
      version: "a1b2c3",
      hashes: [
        {
          alg: "SHA-256",
          content: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
        },
      ],
      properties: [
        {
          name: "traceon:fileFormat",
          value: "safetensors",
        },
        {
          name: "traceon:source",
          value: "huggingface:example-org/llm-7b@a1b2c3",
        },
      ],
    },
    {
      type: "data",
      "bom-ref": "data:fin-qa",
      name: "fin-qa-corpus",
      version: "r7",
      properties: [
        {
          name: "traceon:integrity",
          value: "hash-verified",
        },
      ],
    },
    {
      type: "library",
      "bom-ref": "pkg:transformers",
      name: "transformers",
      version: "4.45.0",
    },
  ],
  dependencies: [
    {
      ref: "model:bank-llm-7b-ft",
      dependsOn: ["model:base", "data:fin-qa", "pkg:transformers"],
    },
  ],
  properties: [
    {
      name: "traceon:scanReport",
      value: "https://traceon.local/v1/scans/sc_003",
    },
    {
      name: "traceon:attestation",
      value: "https://traceon.local/v1/attestations/att_003",
    },
  ],
};

export const MOCK_VERIFY_SUCCESS: VerifyResult = {
  valid: true,
  subject_digest: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
  bom_digest: "c79f8aea781fd506b88e8d3211a5d38d8b2fade4f2c070a28b47a1f0943c246a",
  verdict: "APPROVE",
  attestation_id: "att_003",
  key_id:
    "gcp-kms-projects/traceon-prod/locations/global/keyRings/attestation/cryptoKeys/signer/cryptoKeyVersions/1",
  verified_at: "2026-11-20T10:10:00Z",
};

export const MOCK_VERIFY_FAILURE: VerifyResult = {
  valid: false,
  reason:
    "Digest mismatch: artifact sha256 (3e23e816...) differs from attested subject digest (4b5d1a8e...). The model file was modified after attestation.",
  submitted_digest: "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
  attested_digest: "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
  verified_at: "2026-11-20T10:11:00Z",
};
