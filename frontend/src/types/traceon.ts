export type VerdictStatus = "BLOCK" | "QUARANTINE" | "CONDITIONAL" | "APPROVE";

export type SeverityLevel = "informational" | "low" | "medium" | "high" | "critical";

export type ConfidenceLevel = "low" | "medium" | "high";

export type FindingCategory =
  | "serialization"
  | "weights"
  | "dataset"
  | "dependency"
  | "provenance"
  | "licence"
  | "secrets"
  | "iam"
  | "runtime"
  | "agent";

export interface FindingEvidence {
  module?: string;
  callable?: string;
  offset?: string;
  file?: string;
  sha256?: string;
  [key: string]: unknown;
}

export interface Finding {
  finding_id: string;
  check: string;
  category: FindingCategory;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  deterministic: boolean;
  title: string;
  evidence: FindingEvidence;
  recommendation: string;
  explanation?: string; // Gemini model card explanation if present
}

export interface CheckRun {
  name: string;
  status: "pass" | "warn" | "fail" | "skipped" | "error";
}

export interface ScanArtifact {
  name: string;
  size_bytes: number;
  sha256: string;
  detected_format: string;
}

export interface ScanResult {
  scan_id: string;
  engine_version: string;
  artifact: ScanArtifact;
  checks_run: CheckRun[];
  findings: Finding[];
  started_at: string;
  completed_at: string;
}

export interface Verdict {
  decision_id: string;
  asset_id: string;
  verdict: VerdictStatus;
  reasons: string[];
  policy_id: string;
  policy_version: number;
  decided_at: string;
}

export interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface Asset {
  asset_id: string;
  name: string;
  source: string;
  format: string;
  size_bytes: number;
  sha256: string;
  latest_verdict?: VerdictStatus;
  latest_scan_id?: string;
  attestation_id?: string | null;
  created_at: string;
  verdict?: Verdict;
  findings_summary?: FindingsSummary;
}

export interface InTotoStatement {
  _type: string;
  subject: Array<{
    name: string;
    digest: {
      sha256: string;
    };
  }>;
  predicateType: string;
  predicate: {
    bomDigest: {
      sha256: string;
    };
    scanId: string;
    engineVersion: string;
    policyId: string;
    policyVersion: number;
    verdict: VerdictStatus;
    issuedAt: string;
    expiresAt: string;
  };
}

export interface AttestationEnvelope {
  payloadType: string;
  payload: string;
  statement: InTotoStatement;
  signatures: Array<{
    keyid: string;
    sig: string;
  }>;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  subject_digest?: string;
  bom_digest?: string;
  verdict?: VerdictStatus;
  attestation_id?: string;
  key_id?: string;
  submitted_digest?: string;
  attested_digest?: string;
  verified_at: string;
}

export interface CycloneDXBOM {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: {
      components: Array<{
        type: string;
        name: string;
        version: string;
      }>;
    };
    component: {
      type: string;
      "bom-ref": string;
      name: string;
      version: string;
    };
    properties?: Array<{
      name: string;
      value: string;
    }>;
  };
  components?: Array<{
    type: string;
    "bom-ref": string;
    name: string;
    version?: string;
    hashes?: Array<{
      alg: string;
      content: string;
    }>;
    properties?: Array<{
      name: string;
      value: string;
    }>;
  }>;
  dependencies?: Array<{
    ref: string;
    dependsOn: string[];
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}
