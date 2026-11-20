import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        luxury: {
          cream: "#F7E6CA",     // Warm ivory / cream
          gold: "#E8D59E",      // Warm champagne / soft gold
          rose: "#D9BBB0",      // Dusty rose / warm taupe-blush
          taupe: "#AD9C8E",     // Muted warm slate / elegant taupe
          dark: "#0F0E0D",      // Deepest background
          card: "#161514",      // Elevated card surface
          cardHover: "#1E1C1A", // Hover state
          border: "#2C2825",    // Subtle divider
          borderGold: "rgba(232, 213, 158, 0.25)",
          textPrimary: "#FBF9F5",
          textSecondary: "#C9C1B7",
          textMuted: "#8E867E",
        },
        verdict: {
          block: {
            bg: "rgba(239, 68, 68, 0.12)",
            border: "#EF4444",
            text: "#F87171",
            solid: "#DC2626",
          },
          quarantine: {
            bg: "rgba(245, 158, 11, 0.12)",
            border: "#F59E0B",
            text: "#FBBF24",
            solid: "#D97706",
          },
          conditional: {
            bg: "rgba(59, 130, 246, 0.12)",
            border: "#3B82F6",
            text: "#60A5FA",
            solid: "#2563EB",
          },
          approve: {
            bg: "rgba(16, 185, 129, 0.12)",
            border: "#10B981",
            text: "#34D399",
            solid: "#059669",
          },
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
