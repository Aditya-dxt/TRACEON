import React from "react";
import { fetchAssets, fetchScanResult } from "../services/api";
import { KPICards } from "../components/KPICards";
import { FindingHeroCard } from "../components/FindingHeroCard";
import { ModelTable } from "../components/ModelTable";
import Link from "next/link";
import {
  ShieldAlert,
  FileCheck,
  Cpu,
  ArrowUpRight,
  Sparkles,
  Info,
} from "lucide-react";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const assets = await fetchAssets();
  // Load the evil scan result for the hero card
  const heroScan = await fetchScanResult("sc_001");
  const heroFinding = heroScan?.findings?.[0];

  return (
    <div className="space-y-8">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#282421] pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-serif text-[#E8D59E] bg-[#201D1A] border border-[#E8D59E]/30 mb-2">
            <Sparkles size={13} className="text-[#E8D59E]" />
            <span>Cryptographic &amp; Opcode AI Supply Chain Defense</span>
          </div>
          <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
            Security Posture &amp; Verification Overview
          </h1>
          <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
            Continuous verification of machine learning weights, pickle opcode disassembly, CycloneDX 1.7 AI-BOMs, and Cloud KMS in-toto attestation.
          </p>
        </div>

        {/* Action Quick Links */}
        <div className="flex items-center gap-3">
          <Link
            href="/verify"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-[#161514] bg-gradient-to-r from-[#F7E6CA] to-[#E8D59E] hover:opacity-90 shadow-sm transition-opacity"
          >
            <FileCheck size={14} className="text-[#161514]" />
            <span>Verify Digest</span>
          </Link>
          <Link
            href="/bom"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-[#F7E6CA] bg-[#221F1C] border border-[#3C3632] hover:border-[#E8D59E]/40 transition-colors"
          >
            <Cpu size={14} className="text-[#E8D59E]" />
            <span>AI-BOM Explorer</span>
            <ArrowUpRight size={13} />
          </Link>
        </div>
      </div>

      {/* Posture KPI Metric Cards */}
      <KPICards assets={assets} />

      {/* The Hero View: Worst Finding Card */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-red-400" />
            <h2 className="text-base font-serif font-bold text-[#FBF9F5]">
              Active Critical Finding &bull; Opcode Deserialization Intercept
            </h2>
          </div>
          <span className="text-xs font-mono text-red-400 font-semibold">
            Worst Finding First
          </span>
        </div>
        <FindingHeroCard
          finding={heroFinding}
          verdict="BLOCK"
          assetName={heroScan?.artifact?.name || "evil_model.bin"}
          sha256={heroScan?.artifact?.sha256}
        />
      </div>

      {/* Model Inventory Table */}
      <ModelTable assets={assets} />

      {/* Compliance & Attestation Notice Footer */}
      <div className="rounded-xl border border-[#282421] bg-[#141312] p-4 text-xs text-[#8E867E] flex items-start gap-3">
        <Info size={16} className="text-[#AD9C8E] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="text-[#AD9C8E] leading-relaxed">
            <strong className="text-[#F7E6CA]">Compliance &amp; Trust Notice:</strong> An attestation is evidence, not proof of safety. Deterministic bytecode checks decide policy verdicts (BLOCK, QUARANTINE, CONDITIONAL, APPROVE); Gemini model card extractions provide contextual explanation only.
          </p>
          <p className="text-[11px] text-[#6E6760]">
            Target metrics: Latency &lt; 2 minutes &bull; False positive target &lt; 1% (Engineering goals).
          </p>
        </div>
      </div>
    </div>
  );
}
