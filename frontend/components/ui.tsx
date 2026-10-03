"use client"

import { CircleCheck, CircleDashed, LoaderCircle, OctagonAlert, RefreshCw, TriangleAlert } from "lucide-react"
import type { ButtonHTMLAttributes, ReactNode, Ref, SelectHTMLAttributes } from "react"

import type { Action, RiskLevel } from "@/lib/api"
import { humanize } from "@/lib/format"

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ")
}

// ── layout ─────────────────────────────────────────────────────────────────
export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-2xl">
        <h1 className="font-display text-[28px] leading-tight font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

export function Panel({
  title,
  aside,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode
  aside?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cx("rounded-[var(--radius-panel)] border border-line bg-panel", className)}>
      {(title || aside) && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line px-4 py-3">
          {title && <h2 className="text-[15px] font-semibold">{title}</h2>}
          {aside && <div className="flex min-w-0 items-center gap-2 text-muted">{aside}</div>}
        </div>
      )}
      <div className={bodyClassName ?? "p-4"}>{children}</div>
    </section>
  )
}

/** A single strip of figures divided by hairlines — not a row of identical cards. */
export function FigureStrip({ items }: { items: { label: string; value: ReactNode; hint?: ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-2 overflow-hidden rounded-[var(--radius-panel)] border border-line bg-panel sm:grid-cols-3 xl:grid-cols-6">
      {items.map((it) => (
        <div key={it.label} className="border-line px-4 py-3 [&:not(:last-child)]:border-r max-xl:[&:nth-child(n+4)]:border-t">
          <dt className="text-[13px] text-muted">{it.label}</dt>
          <dd className="mt-0.5 font-display text-[26px] leading-tight font-semibold">{it.value}</dd>
          {it.hint && <dd className="text-xs text-faint">{it.hint}</dd>}
        </div>
      ))}
    </dl>
  )
}

// ── severity & status ──────────────────────────────────────────────────────
const SEVERITY: Record<RiskLevel, { icon: typeof CircleCheck; color: string; label: string }> = {
  LOW: { icon: CircleCheck, color: "var(--color-sev-low)", label: "Low" },
  MEDIUM: { icon: TriangleAlert, color: "var(--color-sev-medium)", label: "Medium" },
  HIGH: { icon: OctagonAlert, color: "var(--color-sev-high)", label: "High" },
}

export function SeverityBadge({ level, score }: { level: RiskLevel | "" | null | undefined; score?: number | null }) {
  if (!level) {
    return (
      <span className="inline-flex items-center gap-1.5 text-faint">
        <CircleDashed size={14} aria-hidden /> Unscored
      </span>
    )
  }
  const s = SEVERITY[level]
  const Icon = s.icon
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[13px] font-medium whitespace-nowrap"
      style={{ borderColor: s.color, background: `color-mix(in srgb, ${s.color} 14%, transparent)` }}
    >
      <Icon size={14} style={{ color: s.color }} aria-hidden />
      {s.label}
      {score !== undefined && score !== null && <span className="text-muted">{score.toFixed(2)}</span>}
    </span>
  )
}

const ACTION_TONE: Record<Action, string> = {
  ALLOW: "text-muted border-line",
  MONITOR: "text-text border-line-strong",
  ESCALATE: "text-text border-[var(--color-sev-medium)]",
  BLOCK: "text-text border-[var(--color-sev-high)]",
}

export function ActionTag({ action }: { action: Action | "" | null | undefined }) {
  if (!action) return <span className="text-faint">—</span>
  return (
    <span className={cx("inline-block rounded border px-1.5 py-px text-[12px] font-semibold tracking-wide", ACTION_TONE[action])}>
      {humanize(action.toLowerCase())}
    </span>
  )
}

const DOT: Record<string, string> = {
  online: "var(--color-ok)", active: "var(--color-ok)", healthy: "var(--color-ok)", loaded: "var(--color-ok)",
  ready: "var(--color-ok)", running: "var(--color-ok)", trained: "var(--color-ok)", enabled: "var(--color-ok)",
  idle: "var(--color-faint)", stopped: "var(--color-faint)", disabled: "var(--color-faint)",
  degraded: "var(--color-warn)", misconfigured: "var(--color-warn)", warning: "var(--color-warn)",
  offline: "var(--color-bad)", error: "var(--color-bad)", unavailable: "var(--color-bad)", unhealthy: "var(--color-bad)",
}

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const key = Object.keys(DOT).find((k) => status.toLowerCase().startsWith(k)) ?? "idle"
  return (
    <span className="inline-flex items-center gap-2">
      <span className="relative inline-flex size-2.5">
        {(key === "active" || key === "running") && (
          <span className="absolute inset-0 animate-ping rounded-full opacity-60 motion-reduce:hidden" style={{ background: DOT[key] }} />
        )}
        <span className="relative inline-flex size-2.5 rounded-full" style={{ background: DOT[key] }} />
      </span>
      <span>{label ?? humanize(status)}</span>
    </span>
  )
}

// ── data bits ──────────────────────────────────────────────────────────────
export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-[12.5px]", className)}>{children}</span>
}

/** Horizontal 0–1 meter with the threshold marked. */
export function ScoreMeter({ value, threshold, label }: { value: number | null | undefined; threshold?: number; label?: string }) {
  const v = Math.max(0, Math.min(1, value ?? 0))
  const color = v > 0.7 ? "var(--color-sev-high)" : v > 0.4 ? "var(--color-sev-medium)" : "var(--color-sev-low)"
  return (
    <div className="flex items-center gap-2" aria-label={label ?? `score ${v.toFixed(2)}`}>
      <div className="relative h-1.5 w-full min-w-16 rounded-full bg-raised">
        <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${v * 100}%`, background: color }} />
        {threshold !== undefined && (
          <div className="absolute -top-1 h-3.5 w-px bg-text/70" style={{ left: `${threshold * 100}%` }} title={`threshold ${threshold}`} />
        )}
      </div>
      <span className="w-9 text-right text-[13px]">{value === null || value === undefined ? "—" : v.toFixed(2)}</span>
    </div>
  )
}

export function Chips({ items, empty = "None" }: { items: string[]; empty?: string }) {
  if (!items.length) return <span className="text-faint">{empty}</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <span key={it} className="rounded border border-line bg-raised px-1.5 py-px text-[12px] text-muted">
          {humanize(it)}
        </span>
      ))}
    </div>
  )
}

// ── controls ───────────────────────────────────────────────────────────────
type Variant = "primary" | "secondary" | "danger" | "ghost"

export function Button({
  variant = "secondary",
  busy,
  icon,
  children,
  className,
  ref,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant
  busy?: boolean
  icon?: ReactNode
  ref?: Ref<HTMLButtonElement>
}) {
  const styles: Record<Variant, string> = {
    primary: "bg-accent text-accent-ink hover:brightness-110 border-accent",
    secondary: "bg-raised text-text border-line-strong hover:border-accent",
    danger: "bg-transparent text-text border-[var(--color-sev-high)] hover:bg-[color-mix(in_srgb,var(--color-sev-high)_18%,transparent)]",
    ghost: "bg-transparent text-muted border-transparent hover:text-text",
  }
  return (
    <button
      ref={ref}
      {...rest}
      disabled={rest.disabled || busy}
      className={cx(
        "inline-flex h-9 items-center gap-2 rounded-md border px-3 text-[14px] font-medium transition-[filter,border-color,color] disabled:cursor-not-allowed disabled:opacity-50",
        styles[variant],
        className,
      )}
    >
      {busy ? <LoaderCircle size={16} className="animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  )
}

export function Select({ label, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement> & { label: string }) {
  return (
    <label className="flex flex-col gap-1 text-[13px] text-muted">
      {label}
      <select
        {...rest}
        className="h-9 min-w-36 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text"
      >
        {children}
      </select>
    </label>
  )
}

// ── states ─────────────────────────────────────────────────────────────────
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-md border border-dashed border-line px-4 py-6">
      <p className="font-medium">{title}</p>
      {children && <div className="text-muted">{children}</div>}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-[var(--color-sev-high)] bg-[color-mix(in_srgb,var(--color-sev-high)_10%,transparent)] px-4 py-3">
      <p className="max-w-2xl">{error.message}</p>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry} icon={<RefreshCw size={14} aria-hidden />}>
          Try again
        </Button>
      )}
    </div>
  )
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-4 animate-pulse rounded bg-raised" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  )
}
