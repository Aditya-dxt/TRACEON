import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { Navbar } from "../components/Navbar";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "Traceon | AI Supply Chain Security & Verification",
  description:
    "Deterministic opcode analysis, CycloneDX 1.7 AI-BOMs, and Cloud KMS in-toto attestation for machine learning models.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} font-sans bg-[#0F0E0D] text-[#FBF9F5] antialiased min-h-screen flex flex-col`}
      >
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-[#24201D] bg-[#121110] py-6 text-xs text-[#8E867E]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="font-serif font-bold text-[#E8D59E]">TRACEON</span>
              <span>&bull;</span>
              <span>DeepTrace AI Team</span>
            </div>
            <p className="text-[11px] text-[#6E6760]">
              The LLM explains; deterministic checks decide. An attestation is evidence, not proof of safety.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
