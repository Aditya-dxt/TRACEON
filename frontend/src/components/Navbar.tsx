"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { API_CONFIG } from "../config";
import {
  Shield,
  Layers,
  FileCheck2,
  Cpu,
  Bot,
  Plug,
} from "lucide-react";

export const Navbar: React.FC = () => {
  const pathname = usePathname();

  const navLinks = [
    { label: "Overview", href: "/", icon: Shield },
    { label: "Model Inventory", href: "/#models", icon: Layers },
    { label: "AI-BOM Explorer", href: "/bom", icon: Cpu },
    { label: "Verify & Attest", href: "/verify", icon: FileCheck2 },
    { label: "Integrations", href: "/integrations", icon: Plug },
  ];

  const previewLinks = [
    { label: "Runtime Guard", href: "/preview/runtime", badge: "MOCKUP" },
    { label: "Agent Security", href: "/preview/agents", badge: "MOCKUP" },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-[#282421] bg-[#121110]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-[#F7E6CA] to-[#E8D59E] p-[1px] shadow-sm">
              <div className="h-full w-full bg-[#161514] rounded-[7px] flex items-center justify-center">
                <span className="font-serif font-black text-[#E8D59E] text-lg tracking-tight group-hover:scale-105 transition-transform">
                  T
                </span>
              </div>
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-serif text-lg font-bold tracking-tight text-[#FBF9F5]">
                  TRACEON
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#282421] text-[#AD9C8E] border border-[#3C3632]">
                  v{API_CONFIG.ENGINE_VERSION}
                </span>
              </div>
              <span className="text-[10px] tracking-wide text-[#AD9C8E] uppercase">
                AI Supply Chain Security
              </span>
            </div>
          </Link>

          {/* Core Navigation */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((link) => {
              const Icon = link.icon;
              const isActive =
                link.href === "/"
                  ? pathname === "/"
                  : pathname?.startsWith(link.href);
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? "text-[#F7E6CA] bg-[#23201D] border border-[#E8D59E]/30"
                      : "text-[#AD9C8E] hover:text-[#FBF9F5] hover:bg-[#1A1816]"
                  }`}
                >
                  <Icon size={14} className={isActive ? "text-[#E8D59E]" : "text-[#8E867E]"} />
                  {link.label}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right side: Mockup Tabs + API Mode Badge */}
        <div className="flex items-center gap-3">
          {/* Roadmap mockups */}
          <div className="hidden lg:flex items-center gap-2 border-r border-[#282421] pr-3">
            {previewLinks.map((p) => {
              const isActive = pathname === p.href;
              return (
                <Link
                  key={p.href}
                  href={p.href}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium border transition-colors ${
                    isActive
                      ? "bg-[#23201D] text-[#D9BBB0] border-[#D9BBB0]/40"
                      : "bg-[#161514] text-[#8E867E] border-[#2C2825] hover:text-[#C9C1B7]"
                  }`}
                >
                  <Bot size={12} className="text-[#D9BBB0]" />
                  <span>{p.label}</span>
                  <span className="text-[9px] font-mono px-1 py-0.2 bg-[#2C2825] text-[#D9BBB0] rounded">
                    {p.badge}
                  </span>
                </Link>
              );
            })}
          </div>

          {/* Mode Badge */}
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border ${
                API_CONFIG.USE_MOCK
                  ? "bg-[#23201D] text-[#E8D59E] border-[#E8D59E]/30"
                  : "bg-emerald-950/40 text-emerald-300 border-emerald-500/40"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${API_CONFIG.USE_MOCK ? "bg-[#E8D59E] animate-pulse" : "bg-emerald-400"}`} />
              {API_CONFIG.USE_MOCK ? "Mock Contract Mode" : "Live FastAPI Connected"}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
