import { API_CONFIG } from "../config";
import {
  Asset,
  ScanResult,
  AttestationEnvelope,
  CycloneDXBOM,
  VerifyResult,
} from "../types/traceon";
import {
  MOCK_ASSETS,
  MOCK_SCANS,
  MOCK_ATTESTATION,
  MOCK_BOM,
  MOCK_VERIFY_SUCCESS,
  MOCK_VERIFY_FAILURE,
} from "../data/mockData";

export async function fetchHealth(): Promise<{ status: string }> {
  if (API_CONFIG.USE_MOCK) {
    return { status: "ok" };
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/health`);
  if (!res.ok) throw new Error("Health check failed");
  return res.json();
}

export async function fetchAssets(): Promise<Asset[]> {
  if (API_CONFIG.USE_MOCK) {
    return MOCK_ASSETS;
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/assets`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to fetch assets" }));
    throw new Error(err.error || "Failed to fetch assets");
  }
  return res.json();
}

export async function fetchAssetById(id: string): Promise<Asset | null> {
  if (API_CONFIG.USE_MOCK) {
    const found = MOCK_ASSETS.find((a) => a.asset_id === id);
    return found || null;
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/assets/${id}`);
  if (!res.ok) {
    if (res.status === 404) return null;
    const err = await res.json().catch(() => ({ error: "Failed to fetch asset" }));
    throw new Error(err.error || "Failed to fetch asset");
  }
  return res.json();
}

export async function fetchScanResult(scanId: string): Promise<ScanResult | null> {
  if (API_CONFIG.USE_MOCK) {
    return MOCK_SCANS[scanId] || null;
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/scans/${scanId}`);
  if (!res.ok) {
    if (res.status === 404) return null;
    const err = await res.json().catch(() => ({ error: "Failed to fetch scan" }));
    throw new Error(err.error || "Failed to fetch scan");
  }
  return res.json();
}

export async function fetchAssetBom(assetId: string): Promise<CycloneDXBOM> {
  if (API_CONFIG.USE_MOCK) {
    return MOCK_BOM;
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/assets/${assetId}/bom`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to fetch BOM" }));
    throw new Error(err.error || "Failed to fetch BOM");
  }
  return res.json();
}

export async function fetchAttestation(attestationId: string): Promise<AttestationEnvelope> {
  if (API_CONFIG.USE_MOCK) {
    return MOCK_ATTESTATION;
  }
  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/attestations/${attestationId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to fetch attestation" }));
    throw new Error(err.error || "Failed to fetch attestation");
  }
  return res.json();
}

export async function verifyDigest(digest: string): Promise<VerifyResult> {
  if (API_CONFIG.USE_MOCK) {
    // If the digest matches the approved model
    if (
      digest.toLowerCase() ===
      "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a".toLowerCase()
    ) {
      return MOCK_VERIFY_SUCCESS;
    }
    return {
      ...MOCK_VERIFY_FAILURE,
      submitted_digest: digest,
      verified_at: new Date().toISOString(),
    };
  }

  const res = await fetch(`${API_CONFIG.BASE_URL}/v1/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sha256: digest }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Verification failed" }));
    throw new Error(err.error || "Verification failed");
  }
  return res.json();
}
