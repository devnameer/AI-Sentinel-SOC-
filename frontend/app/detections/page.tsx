"use client"

import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { BarList } from "@/components/charts"
import {
  ActionTag, Button, Chips, EmptyState, ErrorState, Loading, Mono, PageHeader, Panel, Select, SeverityBadge,
} from "@/components/ui"
import { query, type Analysis, type Evaluation, type EvaluationMetrics, type Page } from "@/lib/api"
import { count, dateTime, humanize, percent, score } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

export default function DetectionsPage() {
  const [kind, setKind] = useState("")
  const [level, setLevel] = useState("")
  const [simulated, setSimulated] = useState("")
  const [selected, setSelected] = useState<string>()
  const [evalRequested, setEvalRequested] = useState(false)
  const list = usePoll<Page<Analysis>>(
    `/analyses${query({ flagged: true, kind, risk_level: level, simulated, limit: 100 })}`, 6000)
  const evaluation = usePoll<Evaluation>(evalRequested ? "/ml/evaluation" : null)

  const techniques: Record<string, number> = {}
  for (const a of list.data?.results ?? []) for (const t of a.mitre_techniques) techniques[t] = (techniques[t] ?? 0) + 1

  return (
    <>
      <PageHeader
        title="Threat detection"
        description="Sessions and network windows the models flagged, with the signals behind each score."
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <Select label="Detector" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">All detectors</option><option value="behavior">Insider behaviour</option><option value="network">Network traffic</option>
            </Select>
            <Select label="Risk" value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="">Any risk</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
            </Select>
            <Select label="Origin" value={simulated} onChange={(e) => setSimulated(e.target.value)}>
              <option value="">Real and simulated</option><option value="false">Real / replay only</option><option value="true">Simulations only</option>
            </Select>
          </div>
          {list.error && <ErrorState error={list.error} onRetry={list.refresh} />}
          {!list.data ? <Panel><Loading rows={6} /></Panel> : list.data.results.length === 0 ? (
            <EmptyState title="Nothing flagged yet">Run an attack simulation or start the live replay to see detections here.</EmptyState>
          ) : (
            <ul className="space-y-3">
              {list.data.results.map((a) => (
                <li key={a.id}>
                  <button onClick={() => setSelected(a.id)} className="block w-full rounded-[var(--radius-panel)] border border-line bg-panel p-4 text-left hover:border-line-strong">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                      <SeverityBadge level={a.risk_level} score={a.risk_score} />
                      <span className="font-medium">{humanize(a.threat_category)}</span>
                      <span className="text-muted">by <Mono>{a.user_id || a.device_id}</Mono></span>
                      {a.is_simulated && <span className="text-[12px] text-[var(--color-series-2)]">simulated</span>}
                      <span className="ml-auto text-[13px] text-muted">{dateTime(a.created_at)}</span>
                    </div>
                    <p className="mt-2 line-clamp-2 text-[13.5px] text-muted">{a.explanation}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-3">
                      <Chips items={a.triggered_rules.slice(0, 5)} />
                      {a.mitre_techniques.map((t) => <Mono key={t} className="text-muted">{t}</Mono>)}
                      <span className="ml-auto flex items-center gap-2 text-[13px] text-muted">anomaly {score(a.score)} <ActionTag action={a.action} /></span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="space-y-5">
          <Panel title="MITRE ATT&CK techniques">
            <BarList data={techniques} empty="No techniques mapped in the loaded detections." />
          </Panel>
          <Panel title="How good is the detector?">
            <p className="text-[13.5px] text-muted">
              Scores the behaviour model against all 133k labelled CERT r4.2 sessions (takes about 10 seconds).
            </p>
            {!evalRequested && <Button className="mt-3" onClick={() => setEvalRequested(true)}>Run evaluation</Button>}
            {evalRequested && !evaluation.data && !evaluation.error && <div className="mt-3"><Loading rows={4} /></div>}
            {evaluation.error && <div className="mt-3"><ErrorState error={evaluation.error} /></div>}
            {evaluation.data && <EvaluationTable e={evaluation.data} />}
          </Panel>
        </div>
      </div>
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={list.refresh} />}
    </>
  )
}

function EvaluationTable({ e }: { e: Evaluation }) {
  const modes: [string, EvaluationMetrics][] = [["IF only", e.isolation_forest], ["Rules only", e.rules_only], ["Hybrid (used)", e.hybrid]]
  const rows: [string, (m: EvaluationMetrics) => string][] = [
    ["ROC-AUC", (m) => m.roc_auc.toFixed(3)],
    ["Avg precision", (m) => m.average_precision.toFixed(3)],
    ["Sessions flagged", (m) => percent(m.flag_rate, 1)],
    ["Session recall", (m) => percent(m.session_recall)],
    ["Insiders caught", (m) => m.malicious_users_flagged],
    ["Benign users flagged", (m) => m.benign_users_flagged],
  ]
  return (
    <div className="mt-3">
      <table className="w-full text-[13px]">
        <thead><tr className="text-muted"><th className="py-1 text-left font-normal">Metric</th>{modes.map(([n]) => <th key={n} className="py-1 text-right font-normal">{n}</th>)}</tr></thead>
        <tbody>
          {rows.map(([label, f]) => (
            <tr key={label} className="border-t border-line/60">
              <td className="py-1 text-muted">{label}</td>
              {modes.map(([n, m]) => <td key={n} className="py-1 text-right">{f(m)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-[12px] leading-snug text-faint">
        {count(e.sessions)} sessions, {e.insider_sessions} inside insider windows, threshold {e.hybrid.threshold}. Labels are window-level, so precision is understated.
      </p>
    </div>
  )
}
