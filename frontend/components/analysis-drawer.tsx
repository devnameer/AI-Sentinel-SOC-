"use client"

import { Check, X } from "lucide-react"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { post, type AnalysisDetail, type Incident } from "@/lib/api"
import { dateTime, EXECUTION_LABEL, humanize, score } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

import { ActionTag, Button, Chips, ErrorState, Loading, Mono, ScoreMeter, SeverityBadge } from "./ui"

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-line px-5 py-4">
      <h3 className="mb-3 text-[14px] font-semibold">{title}</h3>
      {children}
    </section>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 py-1 text-[13.5px]">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  )
}

export function ApprovalBar({ incidentId, recommended, onDone }: { incidentId: number; recommended: string; onDone: () => void }) {
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null)
  const [note, setNote] = useState("")
  const [error, setError] = useState<Error>()
  async function decide(decision: "approve" | "deny") {
    setBusy(decision)
    setError(undefined)
    try {
      await post<Incident>(`/incidents/${incidentId}/decision`, { decision, note })
      onDone()
    } catch (e) {
      setError(e as Error)
    } finally {
      setBusy(null)
    }
  }
  return (
    <div className="space-y-3">
      <p className="text-[13.5px] text-muted">
        Approve to record the recommended <strong className="text-text">{humanize(recommended.toLowerCase())}</strong> action.
        Deny if this is a false positive — the response policy learns from either answer.
      </p>
      <label className="block text-[13px] text-muted">
        Analyst note (optional)
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
          maxLength={2000}
          className="mt-1 w-full rounded-md border border-line-strong bg-raised px-2 py-1.5 text-[14px] text-text"
          placeholder="e.g. Confirmed with the user's manager"
        />
      </label>
      <div className="flex gap-2">
        <Button variant="primary" busy={busy === "approve"} disabled={!!busy} onClick={() => decide("approve")} icon={<Check size={16} />}>
          Approve {humanize(recommended.toLowerCase())}
        </Button>
        <Button variant="danger" busy={busy === "deny"} disabled={!!busy} onClick={() => decide("deny")} icon={<X size={16} />}>
          Deny
        </Button>
      </div>
      {error && <ErrorState error={error} />}
    </div>
  )
}

export function AnalysisDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged?: () => void }) {
  const { data: a, error, refresh } = usePoll<AnalysisDetail>(`/analyses/${id}`)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  const b = a?.details.behavior
  const r = a?.details.risk
  const resp = a?.details.response

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Analysis details">
      <div className="absolute inset-0 bg-black/55" onClick={onClose} />
      <div className="absolute inset-y-0 right-0 flex w-full max-w-[680px] flex-col overflow-y-auto border-l border-line bg-panel">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-line bg-panel px-5 py-4">
          <div className="min-w-0">
            <p className="text-[13px] text-muted">{a ? `${humanize(a.kind)} analysis from ${a.source}` : "Analysis"}</p>
            <h2 className="truncate font-display text-[22px] font-semibold">
              {a ? humanize(a.threat_category || "analysis") : "Loading…"}
            </h2>
            {a && (
              <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
                <Mono>{a.user_id || "—"}</Mono>
                <span>on <Mono>{a.device_id || "unknown device"}</Mono></span>
                <span>{dateTime(a.created_at)}</span>
              </p>
            )}
          </div>
          <Button ref={closeRef} variant="ghost" aria-label="Close details" onClick={onClose} icon={<X size={18} />} />
        </div>

        {error && <div className="p-5"><ErrorState error={error} onRetry={refresh} /></div>}
        {!a && !error && <div className="p-5"><Loading rows={6} /></div>}

        {a && (
          <>
            <div className="grid grid-cols-3 gap-px border-b border-line bg-line">
              <div className="bg-panel px-5 py-3">
                <p className="text-[12px] text-muted">Risk</p>
                <div className="mt-1"><SeverityBadge level={a.risk_level} score={a.risk_score} /></div>
              </div>
              <div className="bg-panel px-5 py-3">
                <p className="text-[12px] text-muted">Response</p>
                <div className="mt-1 flex items-center gap-2"><ActionTag action={a.action} /><span className="text-[13px] text-muted">{EXECUTION_LABEL[a.execution] ?? a.execution}</span></div>
              </div>
              <div className="bg-panel px-5 py-3">
                <p className="text-[12px] text-muted">Ground truth</p>
                <p className="mt-1 text-[13.5px]">
                  {a.ground_truth === null ? "Unknown (live data)" : a.ground_truth ? "Malicious" : "Benign"}
                  {a.is_simulated && <span className="text-muted"> (simulation)</span>}
                </p>
              </div>
            </div>

            {a.incident?.status === "awaiting_approval" && (
              <Section title={`Decision needed for ${a.incident.reference}`}>
                <ApprovalBar incidentId={a.incident.id} recommended={a.incident.recommended_action} onDone={() => { void refresh(); onChanged?.() }} />
              </Section>
            )}

            <Section title="What the agents found">
              <p className="leading-relaxed">{a.explanation || "No explanation recorded."}</p>
              <p className="mt-2 text-[12px] text-faint">
                {a.explanation_source === "llm"
                  ? `Written by ${b?.llm?.provider ?? "the LLM"} ${b?.llm?.model ?? ""} from the model output and knowledge base`
                  : "Template explanation (LLM off, unavailable, or session not flagged)"}
              </p>
              {resp?.summary && a.risk_level !== "LOW" && (
                <div className="mt-4 rounded-md border border-line bg-raised/60 p-3">
                  <p className="text-[13px] text-muted">Incident summary</p>
                  <p className="mt-1">{resp.summary}</p>
                  {resp.playbook.length > 0 && (
                    <ol className="mt-2 list-decimal space-y-1 pl-5 text-[13.5px]">
                      {resp.playbook.map((s) => <li key={s}>{s}</li>)}
                    </ol>
                  )}
                </div>
              )}
            </Section>

            <Section title="Behavior Agent">
              <dl>
                <Row label="Anomaly score"><ScoreMeter value={a.score} threshold={b?.threshold} /></Row>
                {b?.if_score !== undefined && <Row label="Isolation Forest">{score(b.if_score)}</Row>}
                {b?.rule_score !== undefined && <Row label="Rule score">{score(b.rule_score)}</Row>}
                <Row label="Model">{a.model} {b?.scoring_mode && <span className="text-muted">({b.scoring_mode})</span>}</Row>
                <Row label="Baseline">{b?.cold_start ? "New user — cold start, low confidence" : `Confidence ${b?.confidence ?? "—"}`}{b?.baseline_update && <span className="text-muted">, update {b.baseline_update}</span>}</Row>
                <Row label="MITRE ATT&CK"><Chips items={a.mitre_techniques} empty="—" /></Row>
              </dl>
              {b?.dimension_scores && (
                <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2">
                  {Object.entries(b.dimension_scores).map(([k, v]) => (
                    <div key={k}><p className="text-[12px] text-muted">{humanize(k)} deviation</p><ScoreMeter value={v} /></div>
                  ))}
                </div>
              )}
              {a.triggered_rules.length > 0 && (
                <ul className="mt-4 space-y-2">
                  {a.triggered_rules.map((rule) => (
                    <li key={rule} className="text-[13.5px]">
                      <span className="font-medium">{humanize(rule)}</span>
                      {b?.rule_explanations?.[rule] && <span className="text-muted"> — {b.rule_explanations[rule]}</span>}
                    </li>
                  ))}
                </ul>
              )}
              {!!b?.knowledge?.length && (
                <p className="mt-3 text-[12px] text-faint">Knowledge used: {b.knowledge.map((k) => k.title).join("; ")}</p>
              )}
            </Section>

            {r && (
              <Section title="Risk & Decision Agent">
                <dl>
                  <Row label="Calculation">
                    {score(r.base_score)} base
                    {r.llm_adjustment !== 0 && <> {r.llm_adjustment > 0 ? "+" : "−"} {Math.abs(r.llm_adjustment).toFixed(2)} LLM context</>}
                    {r.repeat_offender_penalty > 0 && <> + {r.repeat_offender_penalty.toFixed(2)} repeat offender</>}
                    {" "}= <strong>{score(r.risk_score)}</strong>
                  </Row>
                  <Row label="Method">{r.method === "policy+llm" ? "Policy + LLM review (bounded)" : humanize(r.method)}</Row>
                  <Row label="Policy decision"><ActionTag action={r.decision} /></Row>
                  <Row label="Recommendation">{r.recommended_action}</Row>
                  <Row label="Risk factors"><Chips items={r.risk_factors} /></Row>
                  <Row label="Mitigating"><Chips items={r.mitigating_factors} /></Row>
                </dl>
                <p className="mt-2 text-[13.5px] text-muted">{r.reasoning}</p>
              </Section>
            )}

            {resp && (
              <Section title="Response Agent">
                <dl>
                  <Row label="Final action"><ActionTag action={resp.action} /></Row>
                  <Row label="Policy source">
                    {resp.policy.source === "q_table" ? `Q-learning (state seen ${resp.policy.visits}×)` : humanize(resp.policy.source)}
                  </Row>
                  <Row label="State"><Mono>{resp.policy.state}</Mono></Row>
                  <Row label="Q-values">
                    <div className="flex flex-wrap gap-3 text-[13px]">
                      {Object.entries(resp.policy.q_values).map(([k, v]) => (
                        <span key={k} className={k === resp.policy.recommended_action ? "font-semibold" : "text-muted"}>{humanize(k.toLowerCase())} {v.toFixed(2)}</span>
                      ))}
                    </div>
                  </Row>
                  {resp.policy.guardrail && <Row label="Guardrail">{resp.policy.guardrail}</Row>}
                </dl>
              </Section>
            )}

            <Section title="Agent trace">
              <ol className="space-y-2">
                {[...a.runs].sort((x, y) => x.started_at.localeCompare(y.started_at)).map((run) => (
                  <li key={run.id} className="rounded-md border border-line px-3 py-2">
                    <div className="flex items-center justify-between gap-3 text-[13.5px]">
                      <span className="font-medium">{humanize(run.agent)}</span>
                      <span className="text-muted">{run.duration_ms.toFixed(0)} ms</span>
                    </div>
                    <p className="text-[13px] text-muted">{run.error || run.summary}</p>
                    {!!run.details.tool_calls?.length && (
                      <p className="mt-1 text-[12px] text-faint">
                        MCP: {run.details.tool_calls.map((t) => `${t.tool}${t.ok ? "" : " (failed)"}`).join(", ")}
                      </p>
                    )}
                    {run.details.llm && (
                      <p className="text-[12px] text-faint">
                        LLM: {run.details.llm.provider} {run.details.llm.model} {run.details.llm.ok ? `${run.details.llm.latency_ms} ms` : `failed — ${run.details.llm.error}`}
                      </p>
                    )}
                  </li>
                ))}
              </ol>
            </Section>

            <Section title={`Telemetry (${a.events.length} events)`}>
              <ul className="divide-y divide-line text-[13px]">
                {a.events.slice(0, 40).map((e) => (
                  <li key={e.id} className="flex gap-3 py-1.5">
                    <span className="w-40 shrink-0 text-muted">{dateTime(e.timestamp)}</span>
                    <span className="w-32 shrink-0">{humanize(e.event_type)}</span>
                    <Mono className="truncate text-muted">{e.resource}</Mono>
                  </li>
                ))}
              </ul>
            </Section>
          </>
        )}
      </div>
    </div>
  )
}
