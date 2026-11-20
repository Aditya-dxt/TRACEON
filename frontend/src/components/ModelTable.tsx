"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Asset } from "../types/traceon";
import { VerdictBadge } from "./VerdictBadge";
import {
  Search,
  ArrowRight,
  Copy,
  Check,
  Package,
} from "lucide-react";

interface ModelTableProps {
  assets: Asset[];
}

export const ModelTable: React.FC<ModelTableProps> = ({ assets }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedVerdict, setSelectedVerdict] = useState<string>("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyDigest = (digest: string, id: string) => {
    navigator.clipboard.writeText(digest);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredAssets = assets.filter((asset) => {
    const verdict = asset.latest_verdict || asset.verdict?.verdict || "UNKNOWN";
    const matchesVerdict =
      selectedVerdict === "ALL" || verdict === selectedVerdict;
    const matchesSearch =
      asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.sha256.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesVerdict && matchesSearch;
  });

  return (
    <div id="models" className="rounded-2xl border border-[#282421] bg-[#161514] overflow-hidden">
      {/* Table Controls */}
      <div className="p-4 sm:p-5 border-b border-[#282421] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-serif font-bold text-[#FBF9F5] flex items-center gap-2">
            <Package size={18} className="text-[#E8D59E]" />
            Model Inventory &amp; Assessment Pipeline
          </h2>
          <p className="text-xs text-[#AD9C8E] mt-0.5">
            Cryptographic verification and opcode inspection across all ingested artifacts
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Search Box */}
          <div className="relative">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8E867E]"
            />
            <input
              type="text"
              placeholder="Search by name, repo, or digest..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="h-8 pl-8 pr-3 text-xs rounded-lg bg-[#1E1C1A] border border-[#332E2A] text-[#FBF9F5] placeholder-[#8E867E] focus:outline-none focus:border-[#E8D59E]/60 w-56 sm:w-64"
            />
          </div>

          {/* Verdict Filter Buttons */}
          <div className="flex items-center gap-1 bg-[#1A1816] p-1 rounded-lg border border-[#282421]">
            {["ALL", "BLOCK", "QUARANTINE", "CONDITIONAL", "APPROVE"].map(
              (verdict) => (
                <button
                  key={verdict}
                  onClick={() => setSelectedVerdict(verdict)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium font-mono transition-colors ${
                    selectedVerdict === verdict
                      ? "bg-[#2A2622] text-[#F7E6CA] border border-[#E8D59E]/40"
                      : "text-[#AD9C8E] hover:text-[#FBF9F5]"
                  }`}
                >
                  {verdict}
                </button>
              )
            )}
          </div>
        </div>
      </div>

      {/* Table view */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-[#C9C1B7]">
          <thead className="bg-[#121110] border-b border-[#282421] text-[11px] uppercase tracking-wider text-[#AD9C8E]">
            <tr>
              <th className="py-3 px-4 font-medium">Model / Repository</th>
              <th className="py-3 px-4 font-medium">Format</th>
              <th className="py-3 px-4 font-medium">SHA-256 Digest</th>
              <th className="py-3 px-4 font-medium">Policy Verdict</th>
              <th className="py-3 px-4 font-medium">Findings Summary</th>
              <th className="py-3 px-4 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#221F1C]">
            {filteredAssets.map((asset) => {
              const verdict =
                asset.latest_verdict || asset.verdict?.verdict || "APPROVE";
              const summary = asset.findings_summary || {
                critical: verdict === "BLOCK" ? 1 : 0,
                high: verdict === "QUARANTINE" ? 1 : 0,
                medium: verdict === "CONDITIONAL" ? 1 : 0,
                low: 0,
                informational: verdict === "APPROVE" ? 1 : 0,
              };

              return (
                <tr
                  key={asset.asset_id}
                  className="hover:bg-[#1B1917] transition-colors group"
                >
                  {/* Name and Source */}
                  <td className="py-3.5 px-4">
                    <div className="flex flex-col">
                      <span className="font-semibold text-[#FBF9F5] group-hover:text-[#F7E6CA] transition-colors">
                        {asset.name}
                      </span>
                      <span className="text-[11px] font-mono text-[#AD9C8E] mt-0.5 truncate max-w-xs">
                        {asset.source}
                      </span>
                    </div>
                  </td>

                  {/* Format */}
                  <td className="py-3.5 px-4 font-mono">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] border ${
                        asset.format === "pickle"
                          ? "bg-red-950/30 text-red-300 border-red-500/30"
                          : "bg-[#221F1C] text-[#E8D59E] border-[#38322D]"
                      }`}
                    >
                      {asset.format}
                    </span>
                  </td>

                  {/* SHA-256 Digest */}
                  <td className="py-3.5 px-4 font-mono">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[11px] text-[#AD9C8E]">
                        {asset.sha256.substring(0, 10)}...{asset.sha256.substring(asset.sha256.length - 8)}
                      </span>
                      <button
                        onClick={() => copyDigest(asset.sha256, asset.asset_id)}
                        title="Copy SHA-256"
                        className="text-[#8E867E] hover:text-[#E8D59E] transition-colors"
                      >
                        {copiedId === asset.asset_id ? (
                          <Check size={12} className="text-emerald-400" />
                        ) : (
                          <Copy size={12} />
                        )}
                      </button>
                    </div>
                  </td>

                  {/* Verdict Badge */}
                  <td className="py-3.5 px-4">
                    <VerdictBadge verdict={verdict} size="sm" />
                  </td>

                  {/* Findings Summary */}
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-1.5 font-mono text-[10px]">
                      {summary.critical > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/40 font-bold">
                          {summary.critical} Crit
                        </span>
                      )}
                      {summary.high > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-500/40">
                          {summary.high} High
                        </span>
                      )}
                      {summary.medium > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-500/40">
                          {summary.medium} Med
                        </span>
                      )}
                      {summary.critical === 0 &&
                        summary.high === 0 &&
                        summary.medium === 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                            Clean
                          </span>
                        )}
                    </div>
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right">
                    <Link
                      href={`/models/${asset.asset_id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium text-[#E8D59E] hover:text-[#F7E6CA] bg-[#221F1C] border border-[#38322D] hover:border-[#E8D59E]/40 transition-colors"
                    >
                      <span>Inspect</span>
                      <ArrowRight size={12} />
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
