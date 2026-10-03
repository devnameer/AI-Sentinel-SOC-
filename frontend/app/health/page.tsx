"use client"

import { TriangleAlert } from "lucide-react"
import type { ReactNode } from "react"

import { ErrorState, Loading, Mono, PageHeader, Panel, StatusDot } from "@/components/ui"
import type { Health, ProviderHealth } from "@/lib/api"
import { count, humanize } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

function Item({ name, status, children }: { name: string; status: string; children?: ReactNode }) {
  return (
    <li className="grid gap-1 border-b border-line/60 px-4 py-3 last:border-0 md:grid-cols-[220px_1fr]">
      <StatusDot status={status} label={name} />
      <div className="text-[13.5px] text-muted">
        <span className="text-text">{humanize(status)}</span>{children && <> — {children}</>}
      </div>
    </li>
  )
}

function Provider({ title, p }: { title: string; p: ProviderHealth }) {
  return (
    <div className="rounded-md border border-line p-4">
      <p className="text-[13px] text-muted">{title}</p>
      <p className="mt-1 font-display text-[22px] font-semibold">{p.provider === "none" ? "Disabled" : humanize(p.provider)}</p>
      <p className="text-[13.5px]"><Mono>{p.model || "—"}</Mono></p>
      <div className="mt-3"><StatusDot status={p.status} /></div>
      {p.detail && <p className="mt-2 text-[13px] text-muted">{p.detail}</p>}
      {p.hint && <p className="mt-2 rounded-md bg-raised px-3 py-2 text-[13.5px]">{p.hint}</p>}
      {p.models_available.length > 0 && <p className="mt-2 text-[12px] text-faint">Pulled models: {p.models_available.join(", ")}</p>}
    </div>
  )
}

export default function HealthPage() {
  const { data: h, error, refresh } = usePoll<Health>("/system/health", 10000)
  return (
    <>
      <PageHeader title="System health" description="Every dependency reports its state. Anything optional can be offline; the agents fall back instead of failing." />
      {error && <ErrorState error={error} onRetry={refresh} />}
      {!h ? (!error && <Panel><Loading rows={8} /></Panel>) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-4 rounded-[var(--radius-panel)] border border-line bg-panel px-4 py-3">
            <span className="font-display text-[22px] font-semibold"><StatusDot status={h.status} label={humanize(h.status)} /></span>
            <span className="text-[13px] text-muted">{h.environment.app_env} environment, Python {h.environment.python} on {h.environment.platform}, API auth {h.environment.auth_enabled ? "on" : "off"}</span>
          </div>
          {h.warnings.length > 0 && (
            <ul className="space-y-2">
              {h.warnings.map((w) => (
                <li key={w} className="flex gap-2 rounded-md border border-[var(--color-sev-medium)] bg-[color-mix(in_srgb,var(--color-sev-medium)_10%,transparent)] px-3 py-2 text-[13.5px]">
                  <TriangleAlert size={16} className="mt-0.5 shrink-0 text-[var(--color-sev-medium)]" aria-hidden />{w}
                </li>
              ))}
            </ul>
          )}
          <Panel title="LLM providers" aside={<span className="text-[13px]">{h.components.llm.calls} calls, {h.components.llm.failures} failed, fallback used {h.components.llm.fallback_used}×</span>}>
            <div className="grid gap-4 md:grid-cols-2">
              <Provider title="Primary" p={h.components.llm.primary} />
              {h.components.llm.fallback ? <Provider title="Fallback" p={h.components.llm.fallback} /> : (
                <div className="rounded-md border border-dashed border-line p-4 text-[13.5px] text-muted">
                  No fallback configured. Set <Mono>llm.fallback_provider: groq</Mono> and <Mono>GROQ_API_KEY</Mono> to fail over when Ollama is down.
                </div>
              )}
            </div>
          </Panel>
          <Panel title="Components" bodyClassName="p-0">
            <ul>
              <Item name="Database" status={h.components.database.status}>{h.components.database.engine}{h.components.database.error ? `: ${h.components.database.error}` : ""}</Item>
              <Item name="Behavior model" status={h.components.behavior_model.status}>
                {h.components.behavior_model.error ?? `${h.components.behavior_model.features} features, ${h.components.behavior_model.estimators} trees, ${h.components.behavior_model.scoring_mode} scoring`}
              </Item>
              <Item name="Network model" status={h.components.network_model.status}>
                {Object.entries(h.components.network_model.components).map(([k, v]) => `${humanize(k)} ${v ? "loaded" : "missing"}`).join(", ")}
                {Object.values(h.components.network_model.errors).length > 0 && `. ${Object.values(h.components.network_model.errors).join(". ")}`}
              </Item>
              <Item name="User baselines" status={h.components.baselines.status}>{count(h.components.baselines.users ?? 0)} users</Item>
              <Item name="Response policy" status={h.components.rl_policy.trained_states ? "trained" : "untrained"}>{h.components.rl_policy.trained_states} learned states, {count(h.components.rl_policy.updates)} updates</Item>
              <Item name="Knowledge base (RAG)" status={h.components.retrieval.status}>{h.components.retrieval.backend ?? h.components.retrieval.error ?? ""}{h.components.retrieval.chunks ? `, ${h.components.retrieval.chunks} passages` : ""}</Item>
              <Item name="Replay dataset" status={h.components.replay_dataset.status}>{h.components.replay_dataset.error ?? `${count(h.components.replay_dataset.sessions ?? 0)} CERT sessions, ${h.components.replay_dataset.insider_sessions} in insider windows`}</Item>
              <Item name="MCP tools" status={h.components.mcp.status}>{h.components.mcp.transport} transport</Item>
              <Item name="Live replay" status={h.components.stream.status}>{h.components.stream.batches} batches{h.components.stream.last_error ? `, last error: ${h.components.stream.last_error}` : ""}</Item>
              <Item name="Twilio SMS" status={h.components.twilio.status}>{h.components.twilio.configured ? "credentials present" : "not configured (optional)"}</Item>
            </ul>
          </Panel>
        </div>
      )}
    </>
  )
}
