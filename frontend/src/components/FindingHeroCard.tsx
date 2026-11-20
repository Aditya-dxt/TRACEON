"use client";

import React, { useState } from "react";
import { Finding, VerdictStatus } from "../types/traceon";
import { VerdictBadge } from "./VerdictBadge";
import {
  Binary,
  Copy,
  Check,
  Sparkles,
  AlertOctagon,
  FileCode,
  Fingerprint,
  Info,
} from "lucide-react";

interface FindingHeroCardProps {
  finding?: Finding;
  verdict?: VerdictStatus;
  assetName?: string;
  sha256?: string;
}

export const FindingHeroCard: React.FC<FindingHeroCardProps> = ({
  finding = {
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
      "The disassembled pickle bytecode imports and triggers posix.system at byte offset 0x0042. This grants arbitrary operating system shell command execution during standard deserialization.",
  },
  verdict = "BLOCK",
  assetName = "evil_model.bin",
  sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
}) => {
  const [copiedSha, setCopiedSha] = useState(false);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  return (
    <div className="relative rounded-2xl border-2 border-red-500/30 bg-[#161514] p-6 lg:p-7 shadow-[0_0_40px_rgba(239,68,68,0.08)] overflow-hidden">
      {/* Subtle luxury corner glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-red-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-[#E8D59E]/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#282421] pb-5">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-500/30 text-red-400">
            <AlertOctagon size={24} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-500/30 font-bold">
                {finding.severity}
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#25221F] text-[#E8D59E] border border-[#3C3632]">
                Check: {finding.check}
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#201D1A] text-[#AD9C8E]">
                ID: {finding.finding_id}
              </span>
            </div>
            <h3 className="text-xl font-bold font-serif text-[#FBF9F5] mt-1.5">
              {finding.title}
            </h3>
          </div>
        </div>

        {/* Verdict Badge */}
        <div className="flex items-center gap-2.5 self-start sm:self-center">
          <span className="text-xs font-medium uppercase tracking-wider text-[#AD9C8E]">
            Policy Decision:
          </span>
          <VerdictBadge verdict={verdict} size="lg" />
        </div>
      </div>

      {/* The Evidence Grid (Hero View details) */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-3">
        {/* Module */}
        <div className="bg-[#1D1B19] border border-[#2D2926] rounded-xl p-3.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#AD9C8E] block mb-1">
            Target Module
          </span>
          <div className="flex items-center gap-2">
            <FileCode size={16} className="text-red-400 shrink-0" />
            <span className="font-mono text-sm font-semibold text-red-300">
              {finding.evidence.module || "posix"}
            </span>
          </div>
          <span className="text-[10px] text-[#8E867E] mt-1 block">Deny-listed Python runtime</span>
        </div>

        {/* Callable */}
        <div className="bg-[#1D1B19] border border-[#2D2926] rounded-xl p-3.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#AD9C8E] block mb-1">
            Invoked Callable
          </span>
          <div className="flex items-center gap-2">
            <Binary size={16} className="text-red-400 shrink-0" />
            <span className="font-mono text-sm font-semibold text-red-300">
              {finding.evidence.callable || "system"}
            </span>
          </div>
          <span className="text-[10px] text-[#8E867E] mt-1 block">Arbitrary execution hook</span>
        </div>

        {/* Byte Offset */}
        <div className="bg-[#1D1B19] border border-[#2D2926] rounded-xl p-3.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#AD9C8E] block mb-1">
            Byte Offset
          </span>
          <div className="flex items-center gap-2">
            <span className="font-mono text-base font-bold text-[#F7E6CA]">
              {finding.evidence.offset || "0x0042"}
            </span>
          </div>
          <span className="text-[10px] text-[#8E867E] mt-1 block">Disassembled opcode location</span>
        </div>

        {/* Deterministic status */}
        <div className="bg-[#1D1B19] border border-[#2D2926] rounded-xl p-3.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#AD9C8E] block mb-1">
            Analysis Mode
          </span>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-400"></span>
            <span className="font-mono text-xs font-semibold text-[#FBF9F5]">
              {finding.deterministic ? "Deterministic: TRUE" : "Probabilistic: FALSE"}
            </span>
          </div>
          <span className="text-[10px] text-[#8E867E] mt-1 block">
            Confidence: {finding.confidence.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Artifact SHA-256 Digest Bar */}
      <div className="mt-4 bg-[#181614] border border-[#282421] rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 overflow-hidden">
          <Fingerprint size={16} className="text-[#E8D59E] shrink-0" />
          <div className="flex items-center gap-2 overflow-hidden text-xs">
            <span className="text-[#AD9C8E] font-medium shrink-0">Artifact SHA-256:</span>
            <span className="font-mono text-[#F7E6CA] truncate select-all">{sha256}</span>
          </div>
        </div>
        <button
          onClick={() => copyToClipboard(sha256)}
          className="inline-flex items-center gap-1.5 text-xs text-[#E8D59E] hover:text-[#F7E6CA] px-3 py-1.5 rounded-lg bg-[#221F1C] border border-[#3C3632] hover:border-[#E8D59E]/40 transition-colors shrink-0"
        >
          {copiedSha ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
          <span>{copiedSha ? "Copied" : "Copy Digest"}</span>
        </button>
      </div>

      {/* Disassembly Snippet & Gemini Explanation */}
      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Disassembly Terminal View */}
        <div className="bg-[#0D0C0B] border border-[#282421] rounded-xl p-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-[#201D1A] pb-2 mb-2.5 text-[11px] text-[#8E867E]">
            <span className="flex items-center gap-1.5 text-[#AD9C8E]">
              <Binary size={13} className="text-[#E8D59E]" />
              Disassembled Bytecode ({assetName})
            </span>
            <span className="text-red-400 font-semibold">Violation Detected</span>
          </div>
          <div className="space-y-1 text-[#C9C1B7]">
            <div className="text-[#6E6760]">0x0000: PROTO 4</div>
            <div className="text-[#6E6760]">0x0002: GLOBAL &apos;__builtin__&apos; &apos;getattr&apos;</div>
            <div className="bg-red-950/40 border-l-2 border-red-500 pl-2 text-red-300 font-bold py-0.5">
              0x0042: GLOBAL &apos;posix&apos; &apos;system&apos; &lt;-- [CRITICAL TRIGGER]
            </div>
            <div className="text-[#6E6760]">0x005E: STRING &apos;sh -c &quot;rm -rf /&quot;&apos;</div>
            <div className="text-[#6E6760]">0x0078: REDUCE</div>
            <div className="text-[#6E6760]">0x0079: STOP</div>
          </div>
        </div>

        {/* Gemini Explanation Box */}
        <div className="bg-[#1A1816] border border-[#38322D] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-serif font-bold text-[#E8D59E] mb-2">
              <Sparkles size={14} className="text-[#E8D59E]" />
              <span>Gemini Explanation (Model Card &amp; Bytecode Context)</span>
            </div>
            <p className="text-xs text-[#C9C1B7] leading-relaxed">
              {finding.explanation ||
                "Disassembled pickle opcode invokes posix.system at byte offset 0x0042. This would grant arbitrary command execution upon deserialization."}
            </p>
            <div className="mt-3 p-2 rounded-lg bg-[#141312] border border-[#282421] flex items-start gap-2">
              <Info size={14} className="text-[#AD9C8E] shrink-0 mt-0.5" />
              <p className="text-[11px] text-[#AD9C8E]">
                <strong className="text-[#F7E6CA]">Recommendation:</strong>{" "}
                {finding.recommendation}
              </p>
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-[#282421] flex items-center justify-between text-[10px] text-[#8E867E]">
            <span>Deterministic checks decide &bull; LLM provides explanation</span>
            <span className="font-mono text-[#D9BBB0]">Rule 4.3 #1 Triggered</span>
          </div>
        </div>
      </div>
    </div>
  );
};
