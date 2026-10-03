"use client"

import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { RiskBars } from "@/components/charts"
import { ActionTag, ErrorState, Loading, Mono, PageHeader, Panel, SeverityBadge } from "@/components/ui"
import type { Action, Analysis, Overview, Page, PolicyResponse, PublicConfig } from "@/lib/api"
import { count, EXECUTION_LABEL, humanize, percent, score } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

const ACTIONS: Action[] = ["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]

export default function RiskPage() {
  const [selected, setSelected] = useState<string>()
  const decisions = usePoll<Page<Analysis>>("/analyses?limit=40", 8000)
  const policy = usePoll<PolicyResponse>("/response/policy", 15000)
  const overview = usePoll<Overview>("/stats/overview?hours=24", 15000)
  const config = usePoll<PublicConfig>("/config")
  const t = config.data?.risk.thresholds

  return (
    <>
      <PageHeader
        title="Risk & decisions"
        description="How each anomaly score became a risk level, and how the response policy chose an action."
      />
      <div className="grid gap-5 xl:grid-cols-3">
        <Panel title="Policy bands">
          {t ? (
            <>
              <div className="relative mt-1 mb-6 flex h-3 overflow-hidden rounded-full" aria-hidden>
                <div style={{ width: `${t.low_max * 100}%`, background: "var(--color-sev-low)" }} />
                <div style={{ width: `${(t.medium_max - t.low_max) * 100}%`, background: "var(--color-sev-medium)" }} />
                <div className="flex-1" style={{ background: "var(--color-sev-high)" }} />
              </div>
              <ul className="space-y-2 text-[13.5px]">
                <li className="flex justify-between"><SeverityBadge level="LOW" /><span className="text-muted">below {t.low_max}, logged automatically</span></li>
                <li className="flex justify-between"><SeverityBadge level="MEDIUM" /><span className="text-muted">≤ {t.medium_max}, analyst approval</span></li>
                <li className="flex justify-between"><SeverityBadge level="HIGH" /><span className="text-muted">above {t.medium_max}, at least escalate</span></li>
              </ul>
              <p className="mt-4 text-[13px] text-muted">
                The LLM may adjust a score by at most ±{String(config.data?.agents.risk_agent?.max_llm_adjustment ?? 0.3)}.
                High risk {config.data?.response.auto_execute_high_risk ? "is executed automatically" : "still waits for a human"}.
              </p>
            </>
          ) : <Loading />}
        </Panel>
        <Panel title="Risk distribution, 24 h">{overview.data ? <RiskBars data={overview.data.risk_distribution} /> : <Loading />}</Panel>
        <Panel title="Response policy (Q-learning)">
          {policy.error && <ErrorState error={policy.error} />}
          {policy.data ? (
            <dl className="grid grid-cols-2 gap-y-3 text-[13.5px]">
              <div><dt className="text-muted">Learned states</dt><dd className="font-display text-[22px] font-semibold">{policy.data.stats.trained_states}</dd></div>
              <div><dt className="text-muted">Updates</dt><dd className="font-display text-[22px] font-semibold">{count(policy.data.stats.updates)}</dd></div>
              <div><dt className="text-muted">Good-action rate</dt><dd>{percent(policy.data.stats.metadata.held_out_good_action_rate as number | undefined, 1)} <span className="text-faint">held out</span></dd></div>
              <div><dt className="text-muted">Rule policy</dt><dd>{percent(policy.data.stats.metadata.rule_policy_good_action_rate as number | undefined, 1)} <span className="text-faint">baseline</span></dd></div>
              <div className="col-span-2 text-[12px] text-faint">
                α {policy.data.stats.hyperparameters.alpha}, γ {policy.data.stats.hyperparameters.gamma}, ε {policy.data.stats.hyperparameters.epsilon}.
                Analyst approve / deny updates the table.
              </div>
            </dl>
          ) : <Loading />}
        </Panel>
      </div>

      <Panel title="Decision log" className="mt-5" bodyClassName="p-0">
        {decisions.error && <div className="p-4"><ErrorState error={decisions.error} onRetry={decisions.refresh} /></div>}
        {!decisions.data ? <div className="p-4"><Loading rows={6} /></div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-[13.5px]">
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-normal">Subject</th>
                  <th className="px-2 py-2 font-normal">Anomaly</th>
                  <th className="px-2 py-2 font-normal">Risk</th>
                  <th className="px-2 py-2 font-normal">Policy decision</th>
                  <th className="px-2 py-2 font-normal">Final action</th>
                  <th className="px-4 py-2 font-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {decisions.data.results.map((a) => (
                  <tr key={a.id} className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-raised/50" onClick={() => setSelected(a.id)}>
                    <td className="px-4 py-2"><Mono>{a.user_id || a.device_id}</Mono> <span className="text-muted">{humanize(a.kind)}</span></td>
                    <td className="px-2 py-2">{score(a.score)}</td>
                    <td className="px-2 py-2"><SeverityBadge level={a.risk_level} score={a.risk_score} /></td>
                    <td className="px-2 py-2"><ActionTag action={a.decision} /></td>
                    <td className="px-2 py-2"><ActionTag action={a.action} /></td>
                    <td className="px-4 py-2 text-muted">{EXECUTION_LABEL[a.execution] ?? a.execution}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {decisions.data.results.length === 0 && <p className="p-4 text-faint">No decisions yet.</p>}
          </div>
        )}
      </Panel>

      <Panel title="Learned Q-table" className="mt-5" bodyClassName="p-0"
        aside={<span className="text-[13px]">state = risk level | score bucket | signal count | baseline</span>}>
        {!policy.data ? <div className="p-4"><Loading /></div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[13px]">
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-normal">State</th>
                  <th className="px-2 py-2 text-right font-normal">Visits</th>
                  {ACTIONS.map((a) => <th key={a} className="px-2 py-2 text-right font-normal">{humanize(a.toLowerCase())}</th>)}
                  <th className="px-4 py-2 font-normal">Best</th>
                </tr>
              </thead>
              <tbody>
                {policy.data.table.map((row) => (
                  <tr key={row.state} className="border-b border-line/60 last:border-0">
                    <td className="px-4 py-1.5"><Mono>{row.state}</Mono></td>
                    <td className="px-2 py-1.5 text-right text-muted">{count(row.visits)}</td>
                    {ACTIONS.map((a) => (
                      <td key={a} className={`px-2 py-1.5 text-right ${a === row.best_action ? "font-semibold" : "text-muted"}`}>{row.q_values[a].toFixed(2)}</td>
                    ))}
                    <td className="px-4 py-1.5"><ActionTag action={row.best_action} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={decisions.refresh} />}
    </>
  )
}
