import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        accent: { DEFAULT: "#3b6fe0", weak: "#eaf0fd" },
        ink: { DEFAULT: "#1b2230", 2: "#5a6473", 3: "#8a93a3" },
        surface: "#ffffff",
        rail: "#fbfcfd",
        bg: "#f6f7f9",
        line: "#e4e7ec",
        ok: "#16a34a",
        warn: "#d97706",
        off: "#9aa3b2",
      },
    },
  },
  plugins: [],
} satisfies Config;
