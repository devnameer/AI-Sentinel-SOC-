"use client"

import { CircleCheck, OctagonAlert, TriangleAlert } from "lucide-react"
import {
  Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts"

import type { Overview, RiskLevel } from "@/lib/api"
import { count, humanize } from "@/lib/format"

const AXIS = { stroke: "var(--color-line)", tick: { fill: "var(--color-muted)", fontSize: 12 }, tickLine: false }
const TOOLTIP = {
  contentStyle: {
    background: "var(--color-raised)", border: "1px solid var(--color-line-strong)", borderRadius: 6,
    color: "var(--color-text)", fontSize: 13,
  },
  labelStyle: { color: "var(--color-muted)" },
  cursor: { stroke: "var(--color-line-strong)", fill: "color-mix(in srgb, var(--color-line) 40%, transparent)" },
}

function Legend({ items }: { items: { label: string; color: string; dashed?: boolean }[] }) {
  return (
    <ul className="mb-2 flex flex-wrap gap-4 text-[13px] text-muted">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-2">
          <svg width="18" height="6" aria-hidden>
            <line x1="0" y1="3" x2="18" y2="3" stroke={i.color} strokeWidth="2" strokeDasharray={i.dashed ? "4 3" : undefined} />
          </svg>
          {i.label}
        </li>
      ))}
    </ul>
  )
}

/** Analyses vs flagged per hour — the "threats over time" view. */
export function TimelineChart({ data }: { data: Overview["timeline"] }) {
  const rows = data.map((d) => ({ ...d, label: new Date(d.hour).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) }))
  return (
    <figure>
      <Legend items={[{ label: "Sessions analysed", color: "var(--color-series-1)" }, { label: "Flagged as suspicious", color: "var(--color-series-2)", dashed: true }]} />
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
            <CartesianGrid stroke="var(--color-line)" strokeOpacity={0.6} vertical={false} />
            <XAxis dataKey="label" {...AXIS} interval="preserveStartEnd" minTickGap={28} />
            <YAxis {...AXIS} allowDecimals={false} axisLine={false} />
            <Tooltip {...TOOLTIP} />
            <Line type="monotone" dataKey="analyses" name="Sessions analysed" stroke="var(--color-series-1)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} />
            <Line type="monotone" dataKey="flagged" name="Flagged" stroke="var(--color-series-2)" strokeWidth={2} strokeDasharray="5 3" dot={false} activeDot={{ r: 4 }} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="sr-only">Sessions analysed and flagged per hour over the selected window.</figcaption>
    </figure>
  )
}

/** Distribution of anomaly scores (0–1) — single series, magnitude. */
export function ScoreHistogram({ data, threshold }: { data: Overview["score_histogram"]; threshold?: number }) {
  return (
    <figure>
      <div className="h-44">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -22 }} barCategoryGap={2}>
            <CartesianGrid stroke="var(--color-line)" strokeOpacity={0.6} vertical={false} />
            <XAxis dataKey="bucket" {...AXIS} interval={1} tickFormatter={(b: string) => b.split("–")[0]} />
            <YAxis {...AXIS} allowDecimals={false} axisLine={false} />
            <Tooltip {...TOOLTIP} formatter={(v: unknown) => [String(v), "Sessions"]} labelFormatter={(l: unknown) => `Score ${String(l)}`} />
            <Bar dataKey="count" fill="var(--color-series-1)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      {threshold !== undefined && (
        <figcaption className="mt-1 text-[12px] text-faint">Sessions at or above {threshold} are flagged.</figcaption>
      )}
    </figure>
  )
}

const RISK_META: Record<RiskLevel, { color: string; icon: typeof CircleCheck; label: string }> = {
  LOW: { color: "var(--color-sev-low)", icon: CircleCheck, label: "Low" },
  MEDIUM: { color: "var(--color-sev-medium)", icon: TriangleAlert, label: "Medium" },
  HIGH: { color: "var(--color-sev-high)", icon: OctagonAlert, label: "High" },
}

/** Risk distribution: status colours, always with icon + label + value. */
export function RiskBars({ data }: { data: Record<RiskLevel, number> }) {
  const total = Math.max(1, data.LOW + data.MEDIUM + data.HIGH)
  return (
    <ul className="space-y-3">
      {(["HIGH", "MEDIUM", "LOW"] as RiskLevel[]).map((lvl) => {
        const m = RISK_META[lvl]
        const Icon = m.icon
        const share = data[lvl] / total
        return (
          <li key={lvl} title={`${m.label}: ${data[lvl]} (${Math.round(share * 100)}%)`}>
            <div className="mb-1 flex items-center justify-between text-[13px]">
              <span className="flex items-center gap-1.5"><Icon size={14} style={{ color: m.color }} aria-hidden />{m.label}</span>
              <span className="text-muted">{count(data[lvl])} <span className="text-faint">({Math.round(share * 100)}%)</span></span>
            </div>
            <div className="h-2 rounded-full bg-raised">
              <div className="h-2 rounded-full" style={{ width: `${Math.max(share * 100, data[lvl] ? 1.5 : 0)}%`, background: m.color }} />
            </div>
          </li>
        )
      })}
    </ul>
  )
}

/** Ranked horizontal bars for one measure (attack types, actions…). */
export function BarList({ data, empty = "Nothing recorded yet." }: { data: Record<string, number>; empty?: string }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...rows.map(([, v]) => v))
  if (!rows.length || rows.every(([, v]) => v === 0)) return <p className="text-faint">{empty}</p>
  return (
    <ul className="space-y-2.5">
      {rows.map(([k, v]) => (
        <li key={k} title={`${humanize(k)}: ${v}`}>
          <div className="mb-1 flex justify-between gap-3 text-[13px]">
            <span className="truncate">{/^[A-Z_]+$/.test(k) ? humanize(k.toLowerCase()) : humanize(k)}</span>
            <span className="text-muted">{count(v)}</span>
          </div>
          <div className="h-2 rounded-full bg-raised">
            <div className="h-2 rounded-full bg-[var(--color-series-1)]" style={{ width: `${(v / max) * 100}%`, minWidth: v ? 4 : 0 }} />
          </div>
        </li>
      ))}
    </ul>
  )
}
