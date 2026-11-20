import React from "react";
import {
  Plug,
  Key,
  GitBranch,
  Cloud,
  Server,
} from "lucide-react";

export default function IntegrationsPage() {
  const integrations = [
    {
      name: "Hugging Face Hub Connector",
      type: "Model Registry & Ingestion",
      status: "Connected (Read-Only)",
      details:
        "Automated quarantine sandbox ingestion of safetensors, PyTorch pickles, and ONNX weights via scoped read token.",
      icon: Cloud,
      active: true,
      tag: "Live Integration",
    },
    {
      name: "Google Cloud KMS",
      type: "Cryptographic Attestation Signing",
      status: "Configured (DSSE / in-toto)",
      details:
        "Hardware-backed asymmetrical signing of scan verdicts and CycloneDX 1.7 AI-BOMs.",
      icon: Key,
      active: true,
      tag: "Live Integration",
    },
    {
      name: "GitHub Actions Gate (CI/CD)",
      type: "Supply Chain Pipeline Enforcement",
      status: "Action Available",
      details:
        "Fails pull requests and release pipelines immediately if deployed weights lack a valid Cloud KMS attestation.",
      icon: GitBranch,
      active: true,
      tag: "Live Integration",
    },
    {
      name: "Cloud Run Sandbox Worker",
      type: "Isolated Dynamic Quarantine",
      status: "Egress Disabled",
      details:
        "Zero-egress container sandbox for opcode disassembly and tensor statistics inspection.",
      icon: Server,
      active: true,
      tag: "Live Integration",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-[#282421] pb-6">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-[#E8D59E] bg-[#201D1A] border border-[#E8D59E]/30 mb-2">
          <Plug size={13} className="text-[#E8D59E]" />
          <span>Ecosystem &amp; Cloud Connectors</span>
        </div>
        <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
          Integrations &amp; Infrastructure
        </h1>
        <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
          Connectors powering the Traceon security pipeline across model registries, cryptographic key management, and CI/CD pipelines.
        </p>
      </div>

      {/* Integration Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {integrations.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.name}
              className="rounded-2xl border border-[#282421] bg-[#161514] p-6 hover:border-[#E8D59E]/40 transition-colors space-y-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-[#201D1A] border border-[#3C3632] text-[#E8D59E]">
                    <Icon size={20} />
                  </div>
                  <div>
                    <h3 className="text-base font-serif font-bold text-[#FBF9F5]">
                      {item.name}
                    </h3>
                    <span className="text-xs text-[#8E867E] block">
                      {item.type}
                    </span>
                  </div>
                </div>

                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono bg-emerald-950/40 text-emerald-300 border border-emerald-500/30">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                  <span>{item.status}</span>
                </span>
              </div>

              <p className="text-xs text-[#C9C1B7] leading-relaxed">
                {item.details}
              </p>

              <div className="pt-3 border-t border-[#24201D] flex items-center justify-between text-[11px] font-mono text-[#AD9C8E]">
                <span>Status: Operational</span>
                <span className="text-[#E8D59E]">{item.tag}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
