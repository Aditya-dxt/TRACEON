import React from "react";
import { Bot, KeyRound, Terminal } from "lucide-react";

export default function AgentSecurityPreviewPage() {
  return (
    <div className="space-y-8">
      {/* Prominent Mockup Banner */}
      <div className="rounded-xl border border-[#D9BBB0]/40 bg-[#251E1C] p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="px-2.5 py-1 rounded bg-[#3A2A26] text-[#D9BBB0] text-xs font-mono font-bold uppercase tracking-wider border border-[#D9BBB0]/40">
            Preview / Mockup
          </span>
          <span className="text-xs text-[#F7E6CA]">
            Roadmap Item: Autonomous AI agent capability gates &amp; MCP tool call sandboxing.
          </span>
        </div>
      </div>

      <div className="border-b border-[#282421] pb-6">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono text-[#D9BBB0] bg-[#201D1A] border border-[#D9BBB0]/30 mb-2">
          <Bot size={13} className="text-[#D9BBB0]" />
          <span>Agentic Governance &bull; Architectural Vision</span>
        </div>
        <h1 className="text-3xl font-serif font-extrabold text-[#FBF9F5] tracking-tight">
          Autonomous Agent Security &amp; Policy Gates
        </h1>
        <p className="text-sm text-[#AD9C8E] mt-1 max-w-2xl">
          Pre-execution policy intercepts for tool calls, dynamic MCP server privileges, and prompt injection mitigation.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-[#201D1A] text-[#D9BBB0]">
              <KeyRound size={20} />
            </div>
            <div>
              <h3 className="text-base font-serif font-bold text-[#FBF9F5]">
                Least-Privilege Tool Scoping [Mockup]
              </h3>
              <span className="text-xs text-[#8E867E]">
                Dynamic Token &amp; Capability Boundaries
              </span>
            </div>
          </div>
          <p className="text-xs text-[#C9C1B7] leading-relaxed">
            Deterministic evaluation of agent intent prior to executing system actions, database write queries, or API payloads.
          </p>
        </div>

        <div className="rounded-2xl border border-[#282421] bg-[#161514] p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-[#201D1A] text-[#E8D59E]">
              <Terminal size={20} />
            </div>
            <div>
              <h3 className="text-base font-serif font-bold text-[#FBF9F5]">
                MCP Call Interceptor [Mockup]
              </h3>
              <span className="text-xs text-[#8E867E]">
                Protocol Sandbox Verification
              </span>
            </div>
          </div>
          <p className="text-xs text-[#C9C1B7] leading-relaxed">
            Cryptographic signing of agent actions back to the underlying model attestation to guarantee auditability.
          </p>
        </div>
      </div>
    </div>
  );
}
