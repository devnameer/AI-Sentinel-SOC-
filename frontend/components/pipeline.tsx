"use client"

import { Crosshair } from "lucide-react"
import Link from "next/link"

import type { AgentStatus } from "@/lib/api"
import { count, timeAgo } from "@/lib/format"

import { cx, StatusDot } from "./ui"

const ORDER = ["data_agent", "behavior_agent", "risk_agent", "response_agent"]

/**
 * The signal path: the four defensive agents as stations on one rail, in the
 * order LangGraph runs them. Every number is real telemetry from AgentRun rows.
 */
export function SignalPath({
  agents,
  live,
  outcomes,
}: {
  agents: AgentStatus[]
  live: boolean
  outcomes: { automated: number; awaiting: number }
}) {
  const byName = Object.fromEntries(agents.map((a) => [a.name, a]))
  const attacker = byName["attacker_agent"]
  return (
    <section aria-label="Agent pipeline" className="rounded-[var(--radius-panel)] border border-line bg-panel">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <h2 className="text-[15px] font-semibold">Signal path</h2>
        <p className="text-[13px] text-muted">
          {live ? "Live replay running" : "Idle"} — every event flows through these agents in order
        </p>
      </div>

      <ol className="grid gap-px bg-line md:grid-cols-4">
        {ORDER.map((name, i) => {
          const a = byName[name]
          return (
            <li key={name} className="bg-panel">
              <Link href={`/agents/${name}`} className="group block h-full px-4 pt-3 pb-5 hover:bg-raised/50">
                {/* the rail: one node per station, a line running on to the next stage */}
                <div aria-hidden className="-mr-4 mb-3 flex items-center gap-2">
                  <span className="size-2.5 shrink-0 rounded-full border-2 border-accent bg-ink" />
                  {i < ORDER.length - 1 ? (
                    <span className="relative h-px flex-1 overflow-hidden bg-line-strong">
                      {live && <span className="signal-pulse absolute inset-y-0 left-0 w-1/4 bg-accent" />}
                    </span>
                  ) : (
                    <span className="h-px w-6 bg-line-strong" />
                  )}
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] text-faint">Stage {i + 1}</span>
                  {a && <StatusDot status={a.status} />}
                </div>
                <h3 className="mt-1 font-display text-[19px] font-semibold group-hover:text-accent">{a?.title ?? name}</h3>
                <p className="text-[13px] leading-snug text-muted">{a?.role}</p>
                <div className="mt-4 flex items-baseline gap-4">
                  <div>
                    <p className="font-display text-[30px] leading-none font-semibold">{count(a?.processed ?? 0)}</p>
                    <p className="text-[12px] text-faint">runs, 24 h</p>
                  </div>
                  <div>
                    <p className="text-[15px] font-medium">{a ? `${Math.round(a.avg_latency_ms)} ms` : "—"}</p>
                    <p className="text-[12px] text-faint">avg latency</p>
                  </div>
                  {a && a.errors > 0 && (
                    <div>
                      <p className="text-[15px] font-medium text-[var(--color-sev-high)]">{a.errors}</p>
                      <p className="text-[12px] text-faint">errors</p>
                    </div>
                  )}
                </div>
                <p className="mt-3 line-clamp-2 min-h-[2.6em] text-[13px] text-muted" title={a?.last_summary}>
                  {a?.last_summary || "No activity yet"}
                </p>
                <p className="mt-1 text-[12px] text-faint">{timeAgo(a?.last_activity)}</p>
              </Link>
            </li>
          )
        })}
      </ol>

      <div className="grid gap-px border-t border-line bg-line sm:grid-cols-3">
        <Link href="/simulation" className="flex items-center gap-3 bg-panel px-4 py-3 hover:bg-raised/50">
          <Crosshair size={18} className="text-[var(--color-series-2)]" aria-hidden />
          <div>
            <p className="text-[14px] font-medium">Attacker Agent feeds stage 1</p>
            <p className="text-[12px] text-muted">{count(attacker?.processed ?? 0)} simulations in 24 h, {timeAgo(attacker?.last_activity)}</p>
          </div>
        </Link>
        <Outcome label="Automated outcome" value={outcomes.automated} hint="Low risk logged or auto-executed" />
        <Outcome label="Human approval" value={outcomes.awaiting} hint="Incidents waiting for approve / deny" href="/incidents" alert={outcomes.awaiting > 0} />
      </div>
    </section>
  )
}

function Outcome({ label, value, hint, href, alert }: { label: string; value: number; hint: string; href?: string; alert?: boolean }) {
  const body = (
    <div className="flex items-center justify-between gap-3">
      <div>
        <p className="text-[14px] font-medium">{label}</p>
        <p className="text-[12px] text-muted">{hint}</p>
      </div>
      <p className={cx("font-display text-[24px] font-semibold", alert && "text-[var(--color-sev-high)]")}>{count(value)}</p>
    </div>
  )
  return href ? (
    <Link href={href} className="bg-panel px-4 py-3 hover:bg-raised/50">{body}</Link>
  ) : (
    <div className="bg-panel px-4 py-3">{body}</div>
  )
}
