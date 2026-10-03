import path from "node:path"

import nextEnv from "@next/env"

// One .env for the whole project: load the repository-root .env (BACKEND_URL, SOC_API_TOKEN).
// Variables are server-side only (no NEXT_PUBLIC_ prefix), so nothing leaks to the browser.
nextEnv.loadEnvConfig(path.resolve(process.cwd(), ".."))

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone", // small production image (see Dockerfile)
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "same-origin" },
        ],
      },
    ]
  },
}

export default nextConfig
