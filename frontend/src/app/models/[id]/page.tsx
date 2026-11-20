import React from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import {
  fetchAssetById,
  fetchScanResult,
  fetchAttestation,
} from "../../../services/api";
import { VerdictBadge } from "../../../components/VerdictBadge";
import { FindingHeroCard } from "../../../components/FindingHeroCard";
import {
  ArrowLeft,
  Fingerprint,
  HardDrive,
  Calendar,
  ShieldAlert,
  Cpu,
  FileCheck2,
  CheckCircle2,
  Lock,
} from "lucide-react";

export const dynamic = "force-dynamic";

export default async function ModelDetailPage({
  params,
}: {
  params: { id: string };
}) {
  const asset = await fetchAssetById(params.id);
  if (!asset) {
    notFound();
  }

  const scanId = asset.latest_scan_id || "sc_001";
  const scan = await fetchScanResult(scanId);
  const verdict = asset.latest_verdict || asset.verdict?.verdict || "APPROVE";
  const attestation = asset.attestation_id
    ? await fetchAttestation(asset.attestation_id)
    : null;

  return (
    <div className="space-y-8">
      {/* Back button */}
      <div>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-[#AD9C8E] hover:text-[#F7E6CA] transition-colors"
        >
          <ArrowLeft size={14} />
          <span>Back to Model Inventory</span>
        </Link>
      </div>

      {/* Asset Header Banner */}
      <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 lg:p-7 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 border-b border-[#282421] pb-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-[#25221F] text-[#E8D59E] border border-[#3C3632]">
                Format: {asset.format}
              </span>
              <span className="text-xs font-mono text-[#AD9C8E]">
                ID: {asset.asset_id}
              </span>
            </div>
            <h1 className="text-2xl lg:text-3xl font-serif font-bold text-[#FBF9F5]">
              {asset.name}
            </h1>
            <p className="text-xs font-mono text-[#AD9C8E] mt-1">
              Source: {asset.source}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <div className="flex flex-col sm:items-end">
              <span className="text-[11px] uppercase tracking-wider text-[#AD9C8E]">
                Security Verdict
              </span>
              <div className="mt-1">
                <VerdictBadge verdict={verdict} size="lg" />
              </div>
            </div>

            <Link
              href="/bom"
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold text-[#F7E6CA] bg-[#221F1C] border border-[#3C3632] hover:border-[#E8D59E]/40 transition-colors"
            >
              <Cpu size={14} className="text-[#E8D59E]" />
              <span>Inspect AI-BOM</span>
            </Link>
          </div>
        </div>

        {/* Metadata Strip */}
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="flex items-center gap-2.5 text-[#AD9C8E]">
            <HardDrive size={16} className="text-[#E8D59E] shrink-0" />
            <div>
              <span className="block text-[10px] uppercase text-[#8E867E]">
                File Size
              </span>
              <span className="font-mono text-[#FBF9F5]">
                {(asset.size_bytes / 1024).toFixed(1)} KB
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-[#AD9C8E]">
            <Calendar size={16} className="text-[#E8D59E] shrink-0" />
            <div>
              <span className="block text-[10px] uppercase text-[#8E867E]">
                Ingested At
              </span>
              <span className="font-mono text-[#FBF9F5]">{asset.created_at}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-[#AD9C8E]">
            <FileCheck2 size={16} className="text-[#E8D59E] shrink-0" />
            <div>
              <span className="block text-[10px] uppercase text-[#8E867E]">
                Scan Engine
              </span>
              <span className="font-mono text-[#FBF9F5]">v0.1.0</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-[#AD9C8E]">
            <Lock size={16} className="text-[#E8D59E] shrink-0" />
            <div>
              <span className="block text-[10px] uppercase text-[#8E867E]">
                Attestation ID
              </span>
              <span className="font-mono text-[#FBF9F5]">
                {asset.attestation_id || "None (Rejected / Pending)"}
              </span>
            </div>
          </div>
        </div>

        {/* Full SHA-256 Digest */}
        <div className="mt-4 p-3 rounded-lg bg-[#11100F] border border-[#282421] flex items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 overflow-hidden font-mono">
            <Fingerprint size={14} className="text-[#E8D59E] shrink-0" />
            <span className="text-[#8E867E] shrink-0">SHA-256:</span>
            <span className="text-[#F7E6CA] select-all truncate">{asset.sha256}</span>
          </div>
          <span className="text-[10px] text-[#8E867E] font-mono shrink-0">
            Immutable digest
          </span>
        </div>
      </div>

      {/* Decision Reasons */}
      {asset.verdict && (
        <div className="rounded-xl border border-[#282421] bg-[#161514] p-5 space-y-2">
          <h3 className="text-xs font-serif font-bold uppercase tracking-wider text-[#AD9C8E]">
            Policy Engine Reasons (Decision: {asset.verdict.decision_id})
          </h3>
          <ul className="space-y-1.5 text-xs text-[#C9C1B7]">
            {asset.verdict.reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 font-mono">
                <span className="text-[#E8D59E]">&bull;</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Findings Section (Worst Finding First) */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-serif font-bold text-[#FBF9F5] flex items-center gap-2">
            <ShieldAlert size={18} className="text-[#E8D59E]" />
            Inspection Findings &amp; Evidence ({scan?.findings?.length || 0})
          </h2>
          <span className="text-xs text-[#8E867E]">
            Worst finding shown first &bull; No secrets logged
          </span>
        </div>

        {scan?.findings && scan.findings.length > 0 ? (
          <div className="space-y-4">
            {scan.findings.map((f) => (
              <FindingHeroCard
                key={f.finding_id}
                finding={f}
                verdict={verdict}
                assetName={asset.name}
                sha256={asset.sha256}
              />
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-emerald-950/60 bg-emerald-950/20 p-6 text-center text-xs text-emerald-300">
            <CheckCircle2 size={24} className="mx-auto mb-2 text-emerald-400" />
            <p className="font-semibold text-sm">No Security Violations Discovered</p>
            <p className="text-emerald-400/80 mt-1">
              Artifact verified safe against known deserialization payloads and weight anomalies.
            </p>
          </div>
        )}
      </div>

      {/* Attestation Card (if approved) */}
      {attestation && (
        <div className="rounded-2xl border border-emerald-950/80 bg-[#141815] p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#232F26] pb-4">
            <div className="flex items-center gap-2.5">
              <FileCheck2 size={20} className="text-emerald-400" />
              <div>
                <h3 className="text-base font-serif font-bold text-[#FBF9F5]">
                  Cloud KMS Cryptographic in-toto Attestation
                </h3>
                <span className="text-xs font-mono text-emerald-300">
                  Envelope: {attestation.payloadType}
                </span>
              </div>
            </div>
            <VerdictBadge verdict="APPROVE" size="md" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="bg-[#0E1210] p-3.5 rounded-xl border border-[#232F26] space-y-1">
              <span className="text-[10px] text-[#8E867E] uppercase block">
                Subject Digest
              </span>
              <p className="text-[#F7E6CA] truncate">
                {attestation.statement.subject[0].digest.sha256}
              </p>
              <span className="text-[10px] text-[#8E867E] uppercase block pt-2">
                BOM Digest
              </span>
              <p className="text-[#E8D59E] truncate">
                {attestation.statement.predicate.bomDigest.sha256}
              </p>
            </div>

            <div className="bg-[#0E1210] p-3.5 rounded-xl border border-[#232F26] space-y-1">
              <span className="text-[10px] text-[#8E867E] uppercase block">
                Signing Key ID (Cloud KMS)
              </span>
              <p className="text-[#C9C1B7] truncate">
                {attestation.signatures[0].keyid}
              </p>
              <span className="text-[10px] text-[#8E867E] uppercase block pt-2">
                DSSE Signature
              </span>
              <p className="text-emerald-400 truncate">
                {attestation.signatures[0].sig}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
