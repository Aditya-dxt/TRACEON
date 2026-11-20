"use client";

import React, { useState } from "react";
import { MOCK_BOM } from "../../data/mockData";
import {
  Cpu,
  Database,
  Package,
  ArrowRight,
  Download,
  Copy,
  Check,
  ShieldCheck,
  FileCode,
} from "lucide-react";

export default function BomExplorerPage() {
  const [activeTab, setActiveTab] = useState<"graph" | "json">("graph");
  const [copied, setCopied] = useState(false);
  const bom = MOCK_BOM;

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(bom, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = () => {
    const dataStr =
      "data:text/json;charset=utf-8," +
      encodeURIComponent(JSON.stringify(bom, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute(
      "download",
      `cyclonedx-bom-${bom.metadata.component.name}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#282421] pb-6">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-[#E8D59E] bg-[#201D1A] border border-[#E8D59E]/30 mb-2">
            <Cpu size={13} className="text-[#E8D59E]" />
            <span>CycloneDX 1.7 AI-BOM Specification</span>
          </div>
          <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
            AI Software Bill of Materials (AI-BOM)
          </h1>
          <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
            Cryptographic lineage graph tracing base foundation model, training corpus, dependencies, and fine-tuned weights.
          </p>
        </div>

        {/* View Switcher and Actions */}
        <div className="flex items-center gap-2.5">
          <div className="flex items-center bg-[#1A1816] p-1 rounded-xl border border-[#282421]">
            <button
              onClick={() => setActiveTab("graph")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === "graph"
                  ? "bg-[#2A2622] text-[#F7E6CA] border border-[#E8D59E]/40"
                  : "text-[#AD9C8E] hover:text-[#FBF9F5]"
              }`}
            >
              Lineage Graph
            </button>
            <button
              onClick={() => setActiveTab("json")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === "json"
                  ? "bg-[#2A2622] text-[#F7E6CA] border border-[#E8D59E]/40"
                  : "text-[#AD9C8E] hover:text-[#FBF9F5]"
              }`}
            >
              Raw CycloneDX JSON
            </button>
          </div>

          <button
            onClick={downloadJson}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold text-[#161514] bg-gradient-to-r from-[#F7E6CA] to-[#E8D59E] hover:opacity-90 transition-opacity"
          >
            <Download size={13} />
            <span>Export BOM</span>
          </button>
        </div>
      </div>

      {activeTab === "graph" ? (
        <div className="space-y-6">
          {/* Metadata Card */}
          <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#282421] pb-4">
              <div>
                <span className="text-xs font-mono uppercase text-[#AD9C8E]">
                  Target AI Component
                </span>
                <h2 className="text-xl font-serif font-bold text-[#FBF9F5] mt-1">
                  {bom.metadata.component.name}
                </h2>
                <span className="text-xs font-mono text-[#E8D59E]">
                  Version: {bom.metadata.component.version} &bull; Ref: {bom.metadata.component["bom-ref"]}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-500/40 flex items-center gap-1.5">
                  <ShieldCheck size={14} className="text-emerald-400" />
                  <span>Lineage Verified</span>
                </span>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono text-[#AD9C8E]">
              <div>
                <span className="text-[10px] uppercase text-[#8E867E] block">BOM Serial</span>
                <span className="text-[#C9C1B7] truncate block">{bom.serialNumber}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-[#8E867E] block">Generated At</span>
                <span className="text-[#C9C1B7]">{bom.metadata.timestamp}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-[#8E867E] block">Specification</span>
                <span className="text-[#F7E6CA]">CycloneDX 1.7 JSON</span>
              </div>
            </div>
          </div>

          {/* Visual AI Supply Chain Graph */}
          <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 lg:p-8">
            <h3 className="text-xs font-serif font-bold uppercase tracking-wider text-[#AD9C8E] mb-6">
              Model Lineage &amp; Supply Chain Dependency Flow
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
              {/* Upstream Components: Base Model & Dataset */}
              <div className="space-y-4">
                {/* Base Model Node */}
                <div className="rounded-xl border border-[#3C3632] bg-[#1E1C1A] p-4 relative group hover:border-[#E8D59E]/60 transition-colors">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="flex items-center gap-1.5 font-mono text-[#E8D59E]">
                      <Cpu size={14} /> Base Model
                    </span>
                    <span className="text-[10px] text-[#8E867E] font-mono">model:base</span>
                  </div>
                  <h4 className="text-sm font-semibold text-[#FBF9F5]">example-org/llm-7b</h4>
                  <p className="text-[11px] font-mono text-[#AD9C8E] mt-1">
                    SHA-256: 4b5d1a8e99...
                  </p>
                  <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-[#161514] text-[#F7E6CA] inline-block border border-[#2C2825]">
                    format: safetensors
                  </div>
                </div>

                {/* Training Dataset Node */}
                <div className="rounded-xl border border-[#3C3632] bg-[#1E1C1A] p-4 relative group hover:border-[#D9BBB0]/60 transition-colors">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="flex items-center gap-1.5 font-mono text-[#D9BBB0]">
                      <Database size={14} /> Dataset Corpus
                    </span>
                    <span className="text-[10px] text-[#8E867E] font-mono">data:fin-qa</span>
                  </div>
                  <h4 className="text-sm font-semibold text-[#FBF9F5]">fin-qa-corpus</h4>
                  <p className="text-[11px] font-mono text-[#AD9C8E] mt-1">
                    Revision: r7 &bull; Integrity: hash-verified
                  </p>
                  <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-[#161514] text-[#D9BBB0] inline-block border border-[#2C2825]">
                    dataset-guard: passed
                  </div>
                </div>

                {/* Package Dependency Node */}
                <div className="rounded-xl border border-[#3C3632] bg-[#1E1C1A] p-4 relative group hover:border-[#AD9C8E]/60 transition-colors">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="flex items-center gap-1.5 font-mono text-[#AD9C8E]">
                      <Package size={14} /> Library
                    </span>
                    <span className="text-[10px] text-[#8E867E] font-mono">pkg:transformers</span>
                  </div>
                  <h4 className="text-sm font-semibold text-[#FBF9F5]">transformers v4.45.0</h4>
                  <p className="text-[11px] font-mono text-[#8E867E] mt-1">
                    Runtime framework component
                  </p>
                </div>
              </div>

              {/* Middle Flow Arrows */}
              <div className="hidden md:flex flex-col items-center justify-center space-y-6 text-[#AD9C8E]">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-[#E8D59E]">
                    Fine-Tuning &amp; Weights
                  </span>
                  <ArrowRight size={18} className="text-[#E8D59E]" />
                </div>
              </div>

              {/* Downstream Component: Fine-Tuned Model */}
              <div>
                <div className="rounded-2xl border-2 border-[#E8D59E]/40 bg-[#1D1B19] p-6 shadow-[0_0_30px_rgba(232,213,158,0.06)]">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="flex items-center gap-1.5 font-mono text-[#E8D59E] font-bold">
                      <Cpu size={16} /> Fine-Tuned Target
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/40 font-bold">
                      VERIFIED
                    </span>
                  </div>
                  <h3 className="text-lg font-serif font-bold text-[#FBF9F5]">
                    bank-llm-7b-ft
                  </h3>
                  <p className="text-xs font-mono text-[#AD9C8E] mt-1">
                    Revision: rev-4
                  </p>

                  <div className="mt-4 pt-4 border-t border-[#2C2825] space-y-2 text-xs font-mono">
                    <div className="text-[11px] text-[#8E867E]">
                      Scan Report: <span className="text-[#F7E6CA]">sc_003</span>
                    </div>
                    <div className="text-[11px] text-[#8E867E]">
                      Attestation: <span className="text-emerald-400">att_003</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Raw JSON Viewer */
        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-5">
          <div className="flex items-center justify-between border-b border-[#282421] pb-3 mb-4">
            <span className="text-xs font-mono text-[#AD9C8E] flex items-center gap-2">
              <FileCode size={14} className="text-[#E8D59E]" />
              CycloneDX 1.7 JSON Payload
            </span>
            <button
              onClick={copyJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-[#E8D59E] hover:text-[#F7E6CA] bg-[#221F1C] border border-[#3C3632]"
            >
              {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
              <span>{copied ? "Copied" : "Copy JSON"}</span>
            </button>
          </div>
          <pre className="p-4 rounded-xl bg-[#0D0C0B] border border-[#282421] font-mono text-xs text-[#C9C1B7] overflow-x-auto max-h-[600px] leading-relaxed">
            {JSON.stringify(bom, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
