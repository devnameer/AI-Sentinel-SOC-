import type { Action, RiskLevel } from "./api"

export function score(value: number | null | undefined, digits = 2): string {
  return value === null || value === undefined ? "—" : value.toFixed(digits)
}

export function percent(value: number | null | undefined, digits = 0): string {
  return value === null || value === undefined ? "—" : `${(value * 100).toFixed(digits)}%`
}

export function count(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : new Intl.NumberFormat("en").format(value)
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "never"
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 5) return "just now"
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return "—"
  return new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })
}

/** "data_exfiltration" → "Data exfiltration" */
export function humanize(value: string | null | undefined): string {
  if (!value) return "—"
  const s = value.replace(/_/g, " ")
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export const RISK_ORDER: RiskLevel[] = ["LOW", "MEDIUM", "HIGH"]
export const ACTION_ORDER: Action[] = ["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]

export const EXECUTION_LABEL: Record<string, string> = {
  logged: "Logged",
  awaiting_approval: "Awaiting approval",
  auto_executed: "Auto-executed",
  approved: "Approved",
  denied: "Denied",
}

export const SIMULATION_LABEL: Record<string, string> = {
  running: "Running",
  detected: "Detected",
  missed: "Missed",
  correctly_ignored: "Correctly ignored",
  false_positive: "False positive",
  error: "Error",
}
