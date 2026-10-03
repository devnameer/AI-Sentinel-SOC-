"use client"

import {
  Activity, Bot, BrainCircuit, Crosshair, FileText, Gauge, HeartPulse, LayoutDashboard, Menu, Radar, Scale,
  Settings, ShieldAlert, X,
} from "lucide-react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { useState, type ReactNode } from "react"

import { post, type Health, type Page, type Incident, type StreamStatus } from "@/lib/api"
import { usePoll } from "@/lib/use-poll"

import { Button, cx, StatusDot } from "./ui"

const NAV: { group: string; items: { href: string; label: string; icon: typeof Gauge }[] }[] = [
  {
    group: "Monitor",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard },
      { href: "/events", label: "Live events", icon: Activity },
      { href: "/detections", label: "Threat detection", icon: Radar },
      { href: "/behavior", label: "Behavior analysis", icon: BrainCircuit },
      { href: "/risk", label: "Risk & decisions", icon: Scale },
      { href: "/incidents", label: "Incidents", icon: ShieldAlert },
    ],
  },
  {
    group: "Agents",
    items: [
      { href: "/agents", label: "Agents", icon: Bot },
      { href: "/simulation", label: "Attack simulation", icon: Crosshair },
    ],
  },
  {
    group: "System",
    items: [
      { href: "/health", label: "System health", icon: HeartPulse },
      { href: "/logs", label: "Logs", icon: FileText },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
]

function NavLinks({ pending, onNavigate }: { pending: number; onNavigate?: () => void }) {
  const pathname = usePathname()
  return (
    <nav aria-label="Main" className="flex flex-col gap-5">
      {NAV.map((g) => (
        <div key={g.group}>
          <p className="px-3 pb-1 text-[12px] text-faint">{g.group}</p>
          <ul className="flex flex-col gap-px">
            {g.items.map(({ href, label, icon: Icon }) => {
              const active = href === "/" ? pathname === "/" : pathname.startsWith(href)
              return (
                <li key={href}>
                  <Link
                    href={href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cx(
                      "flex items-center gap-3 rounded-md px-3 py-2 text-[14px]",
                      active ? "bg-raised text-text shadow-[inset_2px_0_0_var(--color-accent)]" : "text-muted hover:bg-raised/60 hover:text-text",
                    )}
                  >
                    <Icon size={17} aria-hidden />
                    <span className="flex-1">{label}</span>
                    {href === "/incidents" && pending > 0 && (
                      <span className="rounded-full bg-[var(--color-sev-high)] px-1.5 text-[12px] font-semibold text-white" aria-label={`${pending} awaiting approval`}>
                        {pending}
                      </span>
                    )}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2.5 px-3">
      <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden>
        <circle cx="13" cy="13" r="11.5" fill="none" stroke="var(--color-line-strong)" />
        <circle cx="13" cy="13" r="6.5" fill="none" stroke="var(--color-accent)" strokeWidth="1.5" />
        <path d="M13 13 L22 6" stroke="var(--color-accent)" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="18.5" cy="16.5" r="1.8" fill="var(--color-sev-high)" />
      </svg>
      <span className="font-display text-[18px] font-semibold tracking-tight">Sentinel SOC</span>
    </Link>
  )
}

function StreamControl() {
  const { data, refresh } = usePoll<StreamStatus>("/system/stream", 10000)
  const [busy, setBusy] = useState(false)
  const running = data?.status === "running"
  async function toggle() {
    setBusy(true)
    try {
      await post("/system/stream", { action: running ? "stop" : "start", source: "replay" })
      await refresh()
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant={running ? "secondary" : "primary"} onClick={toggle} busy={busy} title="Replays labelled CERT r4.2 sessions through the agent pipeline">
      {running ? "Stop live replay" : "Start live replay"}
    </Button>
  )
}

function LlmIndicator() {
  const { data, error } = usePoll<Health>("/system/health", 30000)
  if (error) return <StatusDot status="offline" label="Backend unreachable" />
  const llm = data?.components.llm
  if (!llm) return <span className="text-faint">Checking services…</span>
  const p = llm.primary
  return (
    <Link href="/health" className="hidden items-center gap-2 rounded-md px-2 py-1 hover:bg-raised md:flex" title={p.hint || p.detail}>
      <StatusDot status={p.status} label={`${p.provider === "none" ? "LLM off" : p.provider}${p.model ? ` ${p.model}` : ""}`} />
    </Link>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const { data: pending } = usePoll<Page<Incident>>("/incidents?status=awaiting_approval&limit=1", 15000)
  const pendingCount = pending?.count ?? 0
  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-ink">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col gap-6 border-r border-line bg-ink px-2 py-5 lg:flex">
        <Brand />
        <NavLinks pending={pendingCount} />
        <p className="mt-auto px-3 text-[12px] leading-snug text-faint">
          Detections run on local models. Containment actions are recorded, never executed on real systems.
        </p>
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 flex w-72 flex-col gap-6 overflow-y-auto border-r border-line bg-ink px-2 py-5">
            <div className="flex items-center justify-between pr-2">
              <Brand />
              <Button variant="ghost" aria-label="Close navigation" onClick={() => setOpen(false)} icon={<X size={18} />} />
            </div>
            <NavLinks pending={pendingCount} onNavigate={() => setOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-ink/90 px-4 backdrop-blur lg:px-8">
          <Button variant="ghost" className="lg:hidden" aria-label="Open navigation" onClick={() => setOpen(true)} icon={<Menu size={18} />} />
          <div className="lg:hidden"><Brand /></div>
          <div className="ml-auto flex items-center gap-3">
            <LlmIndicator />
            <StreamControl />
          </div>
        </header>
        <main id="main" className="w-full max-w-[1500px] flex-1 px-4 py-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  )
}
