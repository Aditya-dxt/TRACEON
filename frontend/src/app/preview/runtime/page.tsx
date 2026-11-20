import React from "react";
import { Activity } from "lucide-react";

export default function RuntimePreviewPage() {
  return (
    <div className="space-y-8">
      {/* Prominent Mockup Banner */}
      <div className="rounded-xl border border-[#D9BBB0]/40 bg-[#251E1C] p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="px-2.5 py-1 rounded bg-[#3A2A26] text-[#D9BBB0] text-xs font-mono font-bold uppercase tracking-wider border border-[#D9BBB0]/40">
            Preview / Mockup
          </span>
          <span className="text-xs text-[#F7E6CA]">
            Roadmap Item: Real-time inference monitoring &amp; activation drift detection. Not yet in live production.
          </span>
        </div>
      </div>

      <div className="border-b border-[#282421] pb-6">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-[#D9BBB0] bg-[#201D1A] border border-[#D9BBB0]/30 mb-2">
          <Activity size={13} className="text-[#D9BBB0]" />
          <span>Post-Deployment Defense &bull; Architectural Vision</span>
        </div>
        <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
          Runtime Monitoring &amp; Activation Drift
        </h1>
        <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
          Live streaming telemetry monitoring tensor activations, outlier logits, and stealth trigger injection in inference pipelines.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 space-y-3">
          <span className="text-xs font-mono text-[#D9BBB0] uppercase">
            Inference Telemetry [Mockup]
          </span>
          <h3 className="text-lg font-serif font-bold text-[#FBF9F5]">
            4.2M Tokens/sec
          </h3>
          <p className="text-xs text-[#8E867E]">
            Zero-latency eBPF instrumentation measuring activation norm shifts across serving clusters.
          </p>
        </div>

        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 space-y-3">
          <span className="text-xs font-mono text-[#D9BBB0] uppercase">
            Anomaly Egress Gate [Mockup]
          </span>
          <h3 className="text-lg font-serif font-bold text-amber-300">
            0 Drift Triggers
          </h3>
          <p className="text-xs text-[#8E867E]">
            Automatic failover to attested reference weights if logit perturbation exceeds threshold.
          </p>
        </div>

        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 space-y-3">
          <span className="text-xs font-mono text-[#D9BBB0] uppercase">
            Guard Policy [Mockup]
          </span>
          <h3 className="text-lg font-serif font-bold text-[#E8D59E]">
            Strict Determinism
          </h3>
          <p className="text-xs text-[#8E867E]">
            The LLM explains anomaly context; deterministic threshold logic triggers traffic rerouting.
          </p>
        </div>
      </div>
    </div>
  );
}
