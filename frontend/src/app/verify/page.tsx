"use client";

import React, { useState } from "react";
import { verifyDigest } from "../../services/api";
import { VerifyResult } from "../../types/traceon";
import { VerdictBadge } from "../../components/VerdictBadge";
import {
  FileCheck2,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  RefreshCw,
  Info,
} from "lucide-react";

export default function VerifyPage() {
  const [digest, setDigest] = useState(
    "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a"
  );
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);

  const cleanDigest =
    "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a";
  const tamperedDigest =
    "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";

  const handleVerify = async (hashToVerify?: string) => {
    const target = hashToVerify || digest;
    setLoading(true);
    try {
      const res = await verifyDigest(target.trim());
      setResult(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Verification request failed";
      setResult({
        valid: false,
        reason: msg,
        verified_at: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-[#282421] pb-6">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-[#E8D59E] bg-[#201D1A] border border-[#E8D59E]/30 mb-2">
          <FileCheck2 size={13} className="text-[#E8D59E]" />
          <span>Cloud KMS in-toto Cryptographic Verifier</span>
        </div>
        <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
          Model Attestation &amp; Verification
        </h1>
        <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
          Verify artifact cryptographic integrity against Cloud KMS-signed in-toto attestation statements. Any single-byte modification immediately breaks the trust chain.
        </p>
      </div>

      {/* Interactive Verification Console */}
      <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 lg:p-7 space-y-6">
        <div>
          <label className="block text-xs font-serif font-bold uppercase tracking-wider text-[#AD9C8E] mb-2">
            Artifact SHA-256 Digest
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Fingerprint
                size={16}
                className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#8E867E]"
              />
              <input
                type="text"
                value={digest}
                onChange={(e) => setDigest(e.target.value)}
                placeholder="Paste 64-character SHA-256 hexadecimal digest..."
                className="w-full h-11 pl-10 pr-4 text-xs font-mono rounded-xl bg-[#1E1C1A] border border-[#332E2A] text-[#FBF9F5] placeholder-[#8E867E] focus:outline-none focus:border-[#E8D59E]/60"
              />
            </div>
            <button
              onClick={() => handleVerify()}
              disabled={loading || !digest}
              className="inline-flex items-center justify-center gap-2 px-6 h-11 rounded-xl text-xs font-bold text-[#161514] bg-gradient-to-r from-[#F7E6CA] to-[#E8D59E] hover:opacity-90 disabled:opacity-50 transition-opacity shrink-0"
            >
              {loading ? (
                <RefreshCw size={14} className="animate-spin" />
              ) : (
                <FileCheck2 size={15} />
              )}
              <span>Verify Attestation</span>
            </button>
          </div>
        </div>

        {/* Demo Quick Presets */}
        <div className="pt-2 border-t border-[#24201D]">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#AD9C8E] block mb-2">
            Demo Scenarios &bull; Quick Test
          </span>
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={() => {
                setDigest(cleanDigest);
                handleVerify(cleanDigest);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-emerald-300 bg-emerald-950/30 border border-emerald-500/30 hover:bg-emerald-950/50 transition-colors"
            >
              <CheckCircle2 size={13} className="text-emerald-400" />
              <span>Clean Model (model.safetensors)</span>
            </button>

            <button
              onClick={() => {
                setDigest(tamperedDigest);
                handleVerify(tamperedDigest);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-300 bg-red-950/30 border border-red-500/30 hover:bg-red-950/50 transition-colors"
            >
              <AlertTriangle size={13} className="text-red-400" />
              <span>Simulate 1-Byte Tamper (Digest Mismatch)</span>
            </button>
          </div>
        </div>
      </div>

      {/* Verification Results Panel */}
      {result && (
        <div
          className={`rounded-2xl border p-6 lg:p-7 transition-all ${
            result.valid
              ? "bg-[#141815] border-emerald-500/40 shadow-[0_0_30px_rgba(16,185,129,0.08)]"
              : "bg-[#191414] border-red-500/40 shadow-[0_0_30px_rgba(239,68,68,0.08)]"
          }`}
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4 border-[#282421]">
            <div className="flex items-center gap-3">
              <div
                className={`p-2.5 rounded-xl border ${
                  result.valid
                    ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-400"
                    : "bg-red-950/60 border-red-500/40 text-red-400"
                }`}
              >
                {result.valid ? <ShieldCheck size={24} /> : <ShieldAlert size={24} />}
              </div>
              <div>
                <h3 className="text-xl font-serif font-bold text-[#FBF9F5]">
                  {result.valid
                    ? "Attestation Cryptographically Valid"
                    : "Attestation Verification FAILED"}
                </h3>
                <span className="text-xs font-mono text-[#AD9C8E]">
                  Verified at: {result.verified_at}
                </span>
              </div>
            </div>

            <div className="self-start sm:self-center">
              <VerdictBadge
                verdict={result.valid ? "APPROVE" : "BLOCK"}
                size="lg"
              />
            </div>
          </div>

          {/* Result Details */}
          <div className="mt-6 space-y-4 text-xs font-mono">
            {result.valid ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-[#0E1210] border border-[#232F26] space-y-2">
                  <span className="text-[10px] text-[#8E867E] uppercase block">
                    Attested Subject Digest
                  </span>
                  <p className="text-[#F7E6CA] select-all break-all">
                    {result.subject_digest}
                  </p>

                  <span className="text-[10px] text-[#8E867E] uppercase block pt-2">
                    Attested AI-BOM Digest
                  </span>
                  <p className="text-[#E8D59E] select-all break-all">
                    {result.bom_digest}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-[#0E1210] border border-[#232F26] space-y-2">
                  <span className="text-[10px] text-[#8E867E] uppercase block">
                    Signing KMS Key Resource
                  </span>
                  <p className="text-[#C9C1B7] select-all break-all">
                    {result.key_id}
                  </p>

                  <span className="text-[10px] text-[#8E867E] uppercase block pt-2">
                    Attestation Reference
                  </span>
                  <p className="text-emerald-400 font-bold">
                    {result.attestation_id}
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#140E0E] border border-[#3C1E1E] space-y-3">
                <div className="flex items-center gap-2 text-red-400 font-bold text-sm">
                  <AlertTriangle size={16} />
                  <span>Violation: {result.reason}</span>
                </div>

                <div className="space-y-2 pt-2 border-t border-[#3C1E1E]">
                  <div>
                    <span className="text-[10px] text-[#8E867E] uppercase block">
                      Submitted Artifact SHA-256:
                    </span>
                    <span className="text-red-300 font-bold break-all select-all">
                      {result.submitted_digest}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-[#8E867E] uppercase block">
                      Attested Cryptographic Digest in Statement:
                    </span>
                    <span className="text-emerald-400 break-all select-all">
                      {result.attested_digest}
                    </span>
                  </div>
                </div>

                <p className="text-[11px] text-[#8E867E] pt-2">
                  Zero-tolerance tamper detection: Byte change altered hash. Deployment blocked in accordance with Policy Rule 4.3 #1.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Trust Notice */}
      <div className="rounded-xl border border-[#282421] bg-[#141312] p-4 text-xs text-[#8E867E] flex items-start gap-3">
        <Info size={16} className="text-[#AD9C8E] shrink-0 mt-0.5" />
        <p className="text-[#AD9C8E] leading-relaxed">
          <strong className="text-[#F7E6CA]">Verification Principle:</strong> An attestation is evidence of cryptographic provenance, not absolute proof of safety. A valid attestation guarantees that the artifact evaluated at scan time matches byte-for-byte what is being deployed.
        </p>
      </div>
    </div>
  );
}
