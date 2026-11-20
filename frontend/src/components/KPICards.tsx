import React from "react";
import { Asset } from "../types/traceon";
import { ShieldAlert, AlertTriangle, ShieldCheck, Layers, Gauge } from "lucide-react";

interface KPICardsProps {
  assets: Asset[];
}

export const KPICards: React.FC<KPICardsProps> = ({ assets }) => {
  const total = assets.length;
  const blocked = assets.filter((a) => (a.latest_verdict || a.verdict?.verdict) === "BLOCK").length;
  const quarantined = assets.filter((a) => (a.latest_verdict || a.verdict?.verdict) === "QUARANTINE").length;
  const approved = assets.filter((a) => (a.latest_verdict || a.verdict?.verdict) === "APPROVE").length;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {/* Total Scanned */}
      <div className="bg-[#161514] border border-[#282421] rounded-xl p-4 relative overflow-hidden group hover:border-[#E8D59E]/40 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#AD9C8E]">
            Model Assets
          </span>
          <div className="p-2 rounded-lg bg-[#201D1A] text-[#E8D59E]">
            <Layers size={16} />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-serif text-[#FBF9F5]">{total}</span>
          <span className="text-xs text-[#8E867E]">registered</span>
        </div>
        <p className="mt-1 text-[11px] text-[#AD9C8E]">Hugging Face & local artifacts</p>
      </div>

      {/* Blocked */}
      <div className="bg-[#161514] border border-red-950/60 rounded-xl p-4 relative overflow-hidden group hover:border-red-500/40 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-red-400">
            Threats Blocked
          </span>
          <div className="p-2 rounded-lg bg-red-950/40 text-red-400">
            <ShieldAlert size={16} />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-serif text-red-400">{blocked}</span>
          <span className="text-xs text-red-400/70">critical findings</span>
        </div>
        <p className="mt-1 text-[11px] text-[#AD9C8E]">Zero-tolerance deterministic reject</p>
      </div>

      {/* Quarantined */}
      <div className="bg-[#161514] border border-amber-950/60 rounded-xl p-4 relative overflow-hidden group hover:border-amber-500/40 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-amber-300">
            Quarantined
          </span>
          <div className="p-2 rounded-lg bg-amber-950/40 text-amber-300">
            <AlertTriangle size={16} />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-serif text-amber-300">{quarantined}</span>
          <span className="text-xs text-amber-300/70">statistical anomalies</span>
        </div>
        <p className="mt-1 text-[11px] text-[#AD9C8E]">Weight outliers pending verification</p>
      </div>

      {/* Approved */}
      <div className="bg-[#161514] border border-emerald-950/60 rounded-xl p-4 relative overflow-hidden group hover:border-emerald-500/40 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-emerald-400">
            Attested & Approved
          </span>
          <div className="p-2 rounded-lg bg-emerald-950/40 text-emerald-400">
            <ShieldCheck size={16} />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-serif text-emerald-300">{approved}</span>
          <span className="text-xs text-emerald-400/70">cryptographically signed</span>
        </div>
        <p className="mt-1 text-[11px] text-[#AD9C8E]">Cloud KMS in-toto attestation</p>
      </div>

      {/* SLA & Engine Targets (Explicitly labeled as goals, not results) */}
      <div className="bg-[#161514] border border-[#282421] rounded-xl p-4 relative overflow-hidden group hover:border-[#D9BBB0]/40 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#D9BBB0]">
            Target Goals
          </span>
          <div className="p-2 rounded-lg bg-[#201D1A] text-[#D9BBB0]">
            <Gauge size={16} />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-1">
          <span className="text-lg font-bold font-mono text-[#F7E6CA]">&lt; 2m</span>
          <span className="text-[11px] text-[#AD9C8E]">scan latency</span>
        </div>
        <p className="mt-1 text-[10px] text-[#8E867E]">
          Target: &lt; 1% false positives <span className="text-[#D9BBB0]">(engineering goals)</span>
        </p>
      </div>
    </div>
  );
};
