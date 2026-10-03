/**
 * Server-side proxy: browser → Next.js → Django.
 *
 * - The backend URL and the optional API token come from server-only env vars
 *   (BACKEND_URL, SOC_API_TOKEN), so the token never reaches the browser.
 * - Only the /api/v1 namespace is reachable; paths are rebuilt from segments.
 */
import { NextRequest, NextResponse } from "next/server"

const BACKEND = (process.env.BACKEND_URL ?? "http://localhost:8000").replace(/\/$/, "")
const TOKEN = process.env.SOC_API_TOKEN ?? ""
const SAFE_SEGMENT = /^[A-Za-z0-9_.:@\-]+$/

async function forward(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params
  if (!path.every((s) => SAFE_SEGMENT.test(s))) {
    return NextResponse.json({ error: { code: "bad_path", message: "Invalid API path." } }, { status: 400 })
  }
  const url = `${BACKEND}/api/v1/${path.join("/")}/${req.nextUrl.search}`
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" }
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`
  const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.text()
  try {
    const res = await fetch(url, { method: req.method, headers, body, cache: "no-store" })
    return new NextResponse(await res.text(), {
      status: res.status,
      headers: { "Content-Type": res.headers.get("Content-Type") ?? "application/json" },
    })
  } catch {
    return NextResponse.json(
      {
        error: {
          code: "backend_unreachable",
          message: `The backend is not reachable at ${BACKEND}. Start it with: cd backend && python manage.py runserver`,
        },
      },
      { status: 502 },
    )
  }
}

export const GET = forward
export const POST = forward
export const PATCH = forward
export const dynamic = "force-dynamic"
