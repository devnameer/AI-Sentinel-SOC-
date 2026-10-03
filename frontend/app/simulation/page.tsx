"use client"

import { Crosshair, Shuffle } from "lucide-react"
import { useState, type ReactNode } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { ActionTag, Button, ErrorState, Loading, Mono, PageHeader, Panel, SeverityBadge, cx } from "@/components/ui"
import { post, type Scenario, type Simulation } from "@/lib/api"
import { count, dateTime, EXECUTION_LABEL, humanize, score, SIMULATION_LABEL } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

interface AttacksResponse { scenarios: Scenario[]; outcomes: Record<string, number>; simulations: Simulation[] }

const OUTCOME_TONE: Record<string, string> = {
  detected: "var(--color-ok)", correctly_ignored: "var(--color-ok)",
  missed: "var(--color-bad)", false_positive: "var(--color-warn)", error: "var(--color-bad)", running: "var(--color-faint)",
}

export default function SimulationPage() {
  const { data, error, refresh } = usePoll<AttacksResponse>("/attacks?limit=30", 8000)
  const [busy, setBusy] = useState<string | null>(null)
  const [targets, setTargets] = useState<Record<string, string>>({})
  const [last, setLast] = useState<Simulation>()
  const [runError, setRunError] = useState<Error>()
  const [selected, setSelected] = useState<string>()

  async function run(scenarioId?: string) {
    setBusy(scenarioId ?? "auto")
    setRunError(undefined)
    try {
      const sim = await post<Simulation>("/attacks/simulate", {
        scenario_id: scenarioId ?? "", target_user: scenarioId ? targets[scenarioId] ?? "" : "",
      })
      setLast(sim)
      await refresh()
    } catch (e) {
      setRunError(e as Error)
    } finally {
      setBusy(null)
    }
  }

  const groups: [string, string, Scenario[]][] = data ? [
    ["Insider threat", "Built from the three CERT r4.2 insider scenarios and played against a real insider's baseline.", data.scenarios.filter((s) => s.kind === "behavior")],
    ["Network", "Flow records shaped like known network attacks, scored by the network model and rules.", data.scenarios.filter((s) => s.kind === "network")],
  ] : []
  const totalRuns = Object.values(data?.outcomes ?? {}).reduce((a, b) => a + b, 0)

  return (
    <>
      <PageHeader
        title="Attack simulation"
        description="The Attacker Agent fabricates telemetry for known attack patterns and feeds it to the pipeline. It never executes anything; the expected outcome is recorded so detection is measured, not assumed."
        actions={<Button variant="primary" onClick={() => run()} busy={busy === "auto"} icon={<Shuffle size={15} aria-hidden />}>Let the attacker choose</Button>}
      />
      {error && <ErrorState error={error} onRetry={refresh} />}
      {runError && <div className="mb-4"><ErrorState error={runError} /></div>}

      {last && <LatestRun sim={last} onOpen={setSelected} />}

      {!data ? <Panel><Loading rows={6} /></Panel> : (
        <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
          <div className="space-y-5">
            {groups.map(([title, blurb, items]) => (
              <Panel key={title} title={title} aside={<span className="text-[13px]">{blurb}</span>} bodyClassName="p-0">
                <ul>
                  {items.map((s) => (
                    <li key={s.id} className="grid gap-3 border-b border-line/60 px-4 py-3 last:border-0 md:grid-cols-[1fr_auto] md:items-center">
                      <div>
                        <p className="font-medium">{s.name} {!s.malicious && <span className="text-[12px] font-normal text-muted">(benign control)</span>}</p>
                        <p className="text-[13px] text-muted">{s.description}</p>
                        <p className="mt-1 text-[12.5px] text-faint">{s.tactic !== "—" ? `${s.tactic}, ` : ""}<Mono>{s.technique}</Mono></p>
                      </div>
                      <div className="flex items-center gap-2">
                        {s.kind === "behavior" && (
                          <label className="text-[12px] text-muted">
                            <span className="sr-only">Target user for {s.name}</span>
                            <select value={targets[s.id] ?? ""} onChange={(e) => setTargets({ ...targets, [s.id]: e.target.value })}
                              className="h-9 rounded-md border border-line-strong bg-raised px-2 text-[13.5px] text-text">
                              <option value="">Random target</option>
                              {s.targets.map((t) => <option key={t} value={t}>{t}</option>)}
                            </select>
                          </label>
                        )}
                        <Button onClick={() => run(s.id)} busy={busy === s.id} disabled={!!busy && busy !== s.id} icon={<Crosshair size={15} aria-hidden />}>Run</Button>
                      </div>
                    </li>
                  ))}
                </ul>
              </Panel>
            ))}
          </div>

          <div className="space-y-5">
            <Panel title="Scorecard" aside={<span className="text-[13px]">{count(totalRuns)} runs</span>}>
              {totalRuns === 0 ? <p className="text-faint">Run a scenario to start the scorecard.</p> : (
                <ul className="space-y-2 text-[13.5px]">
                  {Object.entries(data.outcomes).map(([k, v]) => (
                    <li key={k} className="flex items-center justify-between">
                      <span className="flex items-center gap-2"><span className="size-2.5 rounded-full" style={{ background: OUTCOME_TONE[k] }} />{SIMULATION_LABEL[k] ?? k}</span>
                      <span className="text-muted">{v}</span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-[12.5px] text-faint">Missed attacks and false positives are kept, not hidden: they show where the detectors need work.</p>
            </Panel>
            <Panel title="History" bodyClassName="p-0">
              <ul className="max-h-[620px] overflow-y-auto">
                {data.simulations.map((s) => (
                  <li key={s.id}>
                    <button onClick={() => s.analysis && setSelected(s.analysis.id)} className="w-full border-b border-line/60 px-4 py-2.5 text-left hover:bg-raised/50">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[13.5px] font-medium">{s.name}</span>
                        <span className="flex items-center gap-1.5 text-[12.5px]"><span className="size-2 rounded-full" style={{ background: OUTCOME_TONE[s.status] }} />{SIMULATION_LABEL[s.status]}</span>
                      </div>
                      <p className="text-[12.5px] text-muted"><Mono>{s.target}</Mono>, score {score(s.analysis?.score)}, {dateTime(s.created_at)}</p>
                    </button>
                  </li>
                ))}
                {data.simulations.length === 0 && <li className="p-4 text-faint">No simulations yet.</li>}
              </ul>
            </Panel>
          </div>
        </div>
      )}
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={refresh} />}
    </>
  )
}

/** Attack → detection → analysis → risk → response for the run just executed (a real sequence). */
function LatestRun({ sim, onOpen }: { sim: Simulation; onOpen: (id: string) => void }) {
  const a = sim.analysis
  const steps: { title: string; body: ReactNode; tone?: string }[] = [
    { title: "Attack", body: <>{sim.name} against <Mono>{sim.target}</Mono></> },
    { title: "Detection", body: a ? (a.flagged ? `Flagged, anomaly ${score(a.score)}` : `Not flagged, anomaly ${score(a.score)}`) : "—", tone: a?.flagged ? "var(--color-sev-high)" : undefined },
    { title: "Analysis", body: a?.triggered_rules.length ? a.triggered_rules.slice(0, 3).map(humanize).join(", ") : "No rule fired" },
    { title: "Risk", body: a ? <SeverityBadge level={a.risk_level} score={a.risk_score} /> : "—" },
    { title: "Response", body: a ? <span className="flex flex-wrap items-center gap-2"><ActionTag action={a.action} />{EXECUTION_LABEL[a.execution] ?? a.execution}</span> : "—" },
  ]
  return (
    <section className="mb-5 rounded-[var(--radius-panel)] border border-line bg-panel" aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <h2 className="text-[15px] font-semibold">Latest run: <span style={{ color: OUTCOME_TONE[sim.status] }}>{SIMULATION_LABEL[sim.status]}</span></h2>
        {a && <Button variant="ghost" onClick={() => onOpen(a.id)}>Open full analysis</Button>}
      </div>
      <ol className="grid gap-px bg-line md:grid-cols-5">
        {steps.map((s, i) => (
          <li key={s.title} className="bg-panel px-4 py-3">
            <p className="text-[12px] text-faint">{i + 1}. {s.title}</p>
            <div className={cx("mt-1 text-[13.5px]")} style={s.tone ? { color: s.tone } : undefined}>{s.body}</div>
          </li>
        ))}
      </ol>
      {sim.planner?.method && sim.planner.method !== "user_selected" && (
        <p className="border-t border-line px-4 py-2 text-[12.5px] text-muted">Chosen by {sim.planner.method === "llm" ? "the LLM planner" : "least-tested rotation"}: {sim.planner.reasoning}</p>
      )}
    </section>
  )
}
