"use client"

import { Play } from "lucide-react"
import Link from "next/link"
import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { BarList, RiskBars, ScoreHistogram, TimelineChart } from "@/components/charts"
import { SignalPath } from "@/components/pipeline"
import {
  ActionTag, Button, EmptyState, ErrorState, FigureStrip, Loading, Mono, PageHeader, Panel, Select, SeverityBadge,
  StatusDot,
} from "@/components/ui"
import { post, type AgentStatus, type Analysis, type Health, type Overview, type Page } from "@/lib/api"
import { count, humanize, score, SIMULATION_LABEL, timeAgo } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

export default function OverviewPage() {
  const [hours, setHours] = useState(24)
  const [selected, setSelected] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<Error>()
  const overview = usePoll<Overview>(`/stats/overview?hours=${hours}`, 8000)
  const agents = usePoll<{ results: AgentStatus[] }>("/agents", 8000)
  const recent = usePoll<Page<Analysis>>("/analyses?limit=8", 8000)
  const health = usePoll<Health>("/system/health", 30000)

  async function replay() {
    setBusy(true)
    setActionError(undefined)
    try {
      await post("/events/ingest", { source: "replay", count: 10 })
      await Promise.all([overview.refresh(), agents.refresh(), recent.refresh()])
    } catch (e) {
      setActionError(e as Error)
    } finally {
      setBusy(false)
    }
  }

  const o = overview.data
  const ex = o?.executions ?? {}
  const live = health.data?.components.stream.status === "running"

  return (
    <>
      <PageHeader
        title="Security overview"
        description="What the agents saw, scored and decided. Every figure comes from recorded pipeline runs."
        actions={
          <>
            <Select label="Window" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={168}>Last 7 days</option>
            </Select>
            <Button className="self-end" onClick={replay} busy={busy} icon={<Play size={15} aria-hidden />}>
              Replay 10 sessions
            </Button>
          </>
        }
      />
      {actionError && <div className="mb-4"><ErrorState error={actionError} /></div>}
      {overview.error && <div className="mb-4"><ErrorState error={overview.error} onRetry={overview.refresh} /></div>}

      <div className="space-y-5">
        {agents.data ? (
          <SignalPath
            agents={agents.data.results}
            live={live}
            outcomes={{ automated: (ex.logged ?? 0) + (ex.auto_executed ?? 0), awaiting: ex.awaiting_approval ?? 0 }}
          />
        ) : (
          <Panel><Loading rows={4} /></Panel>
        )}

        {o && (
          <FigureStrip
            items={[
              { label: "Events ingested", value: count(o.totals.events) },
              { label: "Sessions analysed", value: count(o.totals.analyses) },
              { label: "Suspicious", value: count(o.totals.suspicious), hint: o.totals.analyses ? `${Math.round((o.totals.suspicious / o.totals.analyses) * 100)}% of analysed` : undefined },
              { label: "Awaiting approval", value: count(o.totals.active_threats) },
              { label: "Blocked", value: count(o.totals.blocked), hint: `${count(o.totals.escalated)} escalated` },
              { label: "Mean anomaly score", value: score(o.totals.avg_anomaly_score), hint: `mean risk ${score(o.totals.avg_risk_score)}` },
            ]}
          />
        )}

        {o && o.totals.analyses === 0 && (
          <EmptyState title="No activity in this window yet">
            Start the live replay (top right) to stream labelled CERT sessions through the agents, or{" "}
            <Link className="text-accent underline-offset-2 hover:underline" href="/simulation">run an attack simulation</Link>.
          </EmptyState>
        )}

        <div className="grid gap-5 xl:grid-cols-3">
          <Panel title="Threats over time" className="xl:col-span-2" aside={<span className="text-[13px]">per hour</span>}>
            {o ? <TimelineChart data={o.timeline} /> : <Loading />}
          </Panel>
          <Panel title="Risk distribution">
            {o ? <RiskBars data={o.risk_distribution} /> : <Loading />}
            {o && (
              <p className="mt-4 text-[13px] text-muted">
                Low risk is logged automatically. Medium and high risk open an incident for analyst approval.
              </p>
            )}
          </Panel>
        </div>

        <div className="grid gap-5 xl:grid-cols-3">
          <Panel title="Recent decisions" className="xl:col-span-2" bodyClassName="p-0"
            aside={<Link href="/detections" className="text-[13px] text-accent hover:underline">All detections</Link>}>
            {recent.data?.results.length ? (
              <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-left text-[13.5px]">
                <thead className="text-[12px] text-muted">
                  <tr className="border-b border-line">
                    <th className="px-4 py-2 font-normal">Risk</th>
                    <th className="px-2 py-2 font-normal">Subject</th>
                    <th className="px-2 py-2 font-normal max-md:hidden">Finding</th>
                    <th className="px-2 py-2 font-normal">Action</th>
                    <th className="px-4 py-2 text-right font-normal">When</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.data.results.map((a) => (
                    <tr key={a.id} className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-raised/50" onClick={() => setSelected(a.id)}>
                      <td className="px-4 py-2"><SeverityBadge level={a.risk_level} score={a.risk_score} /></td>
                      <td className="px-2 py-2"><Mono>{a.user_id || a.device_id}</Mono>{a.is_simulated && <span className="ml-2 text-[12px] text-[var(--color-series-2)]">simulated</span>}</td>
                      <td className="px-2 py-2 text-muted max-md:hidden">{humanize(a.threat_category)}</td>
                      <td className="px-2 py-2"><ActionTag action={a.action} /></td>
                      <td className="px-4 py-2 text-right text-muted">{timeAgo(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            ) : (
              <div className="p-4">{recent.data ? <p className="text-faint">No decisions yet.</p> : <Loading />}</div>
            )}
          </Panel>
          <Panel title="Detection stack">
            {health.data ? <StackStatus h={health.data} /> : <Loading rows={5} />}
          </Panel>
        </div>

        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <Panel title="Attack types detected">{o ? <BarList data={o.threat_categories} empty="No flagged activity yet." /> : <Loading />}</Panel>
          <Panel title="Response actions">{o ? <BarList data={o.response_actions} /> : <Loading />}</Panel>
          <Panel title="Anomaly scores">{o ? <ScoreHistogram data={o.score_histogram} threshold={health.data?.components.behavior_model.threshold} /> : <Loading />}</Panel>
          <Panel title="Attack simulations" aside={<Link href="/simulation" className="text-[13px] text-accent hover:underline">Run one</Link>}>
            {o ? (
              <BarList
                data={Object.fromEntries(Object.entries(o.simulation_outcomes).map(([k, v]) => [SIMULATION_LABEL[k] ?? k, v]))}
                empty="No simulations in this window."
              />
            ) : <Loading />}
          </Panel>
        </div>
      </div>

      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={recent.refresh} />}
    </>
  )
}

function StackStatus({ h }: { h: Health }) {
  const c = h.components
  const rows: [string, string, string][] = [
    ["LLM", c.llm.primary.status, `${c.llm.primary.provider} ${c.llm.primary.model ?? ""}`],
    ["Behavior model", c.behavior_model.status, `${c.behavior_model.scoring_mode}, threshold ${c.behavior_model.threshold}`],
    ["Network model", c.network_model.status, c.network_model.components.catboost ? "IF + CatBoost" : "IF only"],
    ["Response policy", c.rl_policy.trained_states ? "trained" : "untrained", `${c.rl_policy.trained_states} learned states`],
    ["Knowledge base", c.retrieval.status, `${c.retrieval.backend ?? "—"}, ${c.retrieval.chunks ?? 0} passages`],
    ["Baselines", c.baselines.status, `${count(c.baselines.users ?? 0)} users`],
  ]
  return (
    <ul className="space-y-2.5 text-[13.5px]">
      {rows.map(([label, status, detail]) => (
        <li key={label} className="flex items-start justify-between gap-3">
          <StatusDot status={status} label={label} />
          <span className="text-right text-muted">{detail}</span>
        </li>
      ))}
      {c.llm.primary.status !== "online" && c.llm.primary.hint && (
        <li className="rounded-md border border-line bg-raised/60 px-3 py-2 text-[13px]">{c.llm.primary.hint}</li>
      )}
    </ul>
  )
}
