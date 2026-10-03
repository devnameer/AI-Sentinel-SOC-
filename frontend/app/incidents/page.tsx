"use client"

import { Check, X } from "lucide-react"
import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { ActionTag, Button, Chips, EmptyState, ErrorState, Loading, Mono, PageHeader, Panel, SeverityBadge, cx } from "@/components/ui"
import { post, query, type Incident, type IncidentStatus, type Page } from "@/lib/api"
import { dateTime, humanize, percent, timeAgo } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

const TABS: { key: IncidentStatus | ""; label: string }[] = [
  { key: "awaiting_approval", label: "Awaiting approval" },
  { key: "approved", label: "Approved" },
  { key: "denied", label: "Denied" },
  { key: "auto_executed", label: "Auto-executed" },
  { key: "", label: "All" },
]

export default function IncidentsPage() {
  const [tab, setTab] = useState<IncidentStatus | "">("awaiting_approval")
  const [selected, setSelected] = useState<string>()
  const list = usePoll<Page<Incident>>(`/incidents${query({ status: tab, limit: 60 })}`, 6000)

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Medium and high risk findings wait here for a human decision. Approving records the containment action; nothing touches real systems."
      />
      <div role="tablist" aria-label="Incident status" className="mb-5 flex flex-wrap gap-1 border-b border-line">
        {TABS.map((t) => (
          <button key={t.label} role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            className={cx("-mb-px border-b-2 px-3 py-2 text-[14px]", tab === t.key ? "border-accent text-text" : "border-transparent text-muted hover:text-text")}>
            {t.label}
          </button>
        ))}
      </div>
      {list.error && <ErrorState error={list.error} onRetry={list.refresh} />}
      {!list.data ? <Panel><Loading rows={5} /></Panel> : list.data.results.length === 0 ? (
        <EmptyState title={tab === "awaiting_approval" ? "Nothing is waiting for you" : "No incidents in this view"}>
          Incidents are opened automatically for medium and high risk findings.
        </EmptyState>
      ) : tab === "awaiting_approval" ? (
        <ul className="grid gap-4 lg:grid-cols-2">
          {list.data.results.map((i) => <DecisionCard key={i.id} incident={i} onOpen={() => setSelected(i.analysis.id)} onDone={list.refresh} />)}
        </ul>
      ) : (
        <Panel bodyClassName="p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-[13.5px]">
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-normal">Incident</th><th className="px-2 py-2 font-normal">Severity</th>
                  <th className="px-2 py-2 font-normal">Finding</th><th className="px-2 py-2 font-normal">Recommended</th>
                  <th className="px-2 py-2 font-normal">Outcome</th><th className="px-4 py-2 font-normal">Decided</th>
                </tr>
              </thead>
              <tbody>
                {list.data.results.map((i) => (
                  <tr key={i.id} className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-raised/50" onClick={() => setSelected(i.analysis.id)}>
                    <td className="px-4 py-2"><Mono>{i.reference}</Mono></td>
                    <td className="px-2 py-2"><SeverityBadge level={i.severity} score={i.analysis.risk_score} /></td>
                    <td className="px-2 py-2">{humanize(i.analysis.threat_category)} <span className="text-muted">by <Mono>{i.analysis.user_id || i.analysis.device_id}</Mono></span></td>
                    <td className="px-2 py-2"><ActionTag action={i.recommended_action} /></td>
                    <td className="px-2 py-2">{humanize(i.status)} {i.final_action && <ActionTag action={i.final_action} />}</td>
                    <td className="px-4 py-2 text-muted">{i.decided_at ? `${dateTime(i.decided_at)}, ${i.decided_by}` : dateTime(i.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={list.refresh} />}
    </>
  )
}

function DecisionCard({ incident: i, onOpen, onDone }: { incident: Incident; onOpen: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null)
  const [error, setError] = useState<Error>()
  const a = i.analysis
  const accent = i.severity === "HIGH" ? "var(--color-sev-high)" : "var(--color-sev-medium)"
  async function decide(decision: "approve" | "deny") {
    setBusy(decision)
    setError(undefined)
    try {
      await post(`/incidents/${i.id}/decision`, { decision })
      onDone()
    } catch (e) {
      setError(e as Error)
      setBusy(null)
    }
  }
  return (
    <li className="flex flex-col rounded-[var(--radius-panel)] border bg-panel" style={{ borderColor: accent }}>
      <div className="flex items-start justify-between gap-3 px-4 pt-4">
        <div>
          <SeverityBadge level={i.severity} />
          <h2 className="mt-2 font-display text-[21px] leading-tight font-semibold">{humanize(a.threat_category)}</h2>
          <p className="text-[13px] text-muted"><Mono>{i.reference}</Mono> opened {timeAgo(i.created_at)}{a.is_simulated && ", from a simulation"}</p>
        </div>
        <div className="text-right">
          <p className="font-display text-[34px] leading-none font-semibold">{percent(a.risk_score)}</p>
          <p className="text-[12px] text-muted">risk score</p>
        </div>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 px-4 text-[13.5px]">
        <div><dt className="text-muted">User</dt><dd><Mono>{a.user_id || "—"}</Mono></dd></div>
        <div><dt className="text-muted">Device / host</dt><dd><Mono>{a.device_id || "—"}</Mono></dd></div>
        <div className="col-span-2"><dt className="text-muted">Signals</dt><dd className="mt-1"><Chips items={a.triggered_rules.slice(0, 6)} /></dd></div>
      </dl>
      <p className="mt-3 line-clamp-3 px-4 text-[13.5px] text-muted">{a.explanation}</p>
      <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-line px-4 py-3">
        <span className="mr-auto flex items-center gap-2 text-[13px] text-muted">Recommended <ActionTag action={i.recommended_action} /></span>
        <Button variant="ghost" onClick={onOpen}>Details</Button>
        <Button variant="danger" onClick={() => decide("deny")} busy={busy === "deny"} disabled={!!busy} icon={<X size={15} />}>Deny</Button>
        <Button variant="primary" onClick={() => decide("approve")} busy={busy === "approve"} disabled={!!busy} icon={<Check size={15} />}>Approve</Button>
      </div>
      {error && <div className="px-4 pb-3"><ErrorState error={error} /></div>}
    </li>
  )
}
