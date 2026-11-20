import React from "react";
import { VerdictStatus } from "../types/traceon";
import { ShieldAlert, AlertTriangle, Clock, ShieldCheck } from "lucide-react";

interface VerdictBadgeProps {
  verdict: VerdictStatus;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({
  verdict,
  size = "md",
  showIcon = true,
}) => {
  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs font-semibold tracking-wider",
    md: "px-2.5 py-1 text-xs font-semibold tracking-wider",
    lg: "px-3.5 py-1.5 text-sm font-bold tracking-widest",
  };

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  };

  switch (verdict) {
    case "BLOCK":
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-red-500/40 bg-red-950/40 text-red-400 uppercase font-mono shadow-[0_0_12px_rgba(239,68,68,0.2)] ${sizeClasses[size]}`}
        >
          {showIcon && <ShieldAlert size={iconSizes[size]} className="text-red-400 stroke-[2.5]" />}
          <span>BLOCK</span>
        </span>
      );
    case "QUARANTINE":
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-950/40 text-amber-300 uppercase font-mono shadow-[0_0_12px_rgba(245,158,11,0.2)] ${sizeClasses[size]}`}
        >
          {showIcon && <AlertTriangle size={iconSizes[size]} className="text-amber-400 stroke-[2.5]" />}
          <span>QUARANTINE</span>
        </span>
      );
    case "CONDITIONAL":
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-blue-500/40 bg-blue-950/40 text-blue-300 uppercase font-mono shadow-[0_0_12px_rgba(59,130,246,0.2)] ${sizeClasses[size]}`}
        >
          {showIcon && <Clock size={iconSizes[size]} className="text-blue-400 stroke-[2.5]" />}
          <span>CONDITIONAL</span>
        </span>
      );
    case "APPROVE":
      return (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 uppercase font-mono shadow-[0_0_12px_rgba(16,185,129,0.2)] ${sizeClasses[size]}`}
        >
          {showIcon && <ShieldCheck size={iconSizes[size]} className="text-emerald-400 stroke-[2.5]" />}
          <span>APPROVE</span>
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center gap-1.5 rounded-full border border-luxury-taupe/40 bg-luxury-card text-luxury-taupe ${sizeClasses[size]}`}>
          {verdict}
        </span>
      );
  }
};
