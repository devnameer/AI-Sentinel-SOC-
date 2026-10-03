"use client"

import Link from "next/link"

import { ErrorState, Loading, PageHeader, Panel, StatusDot } from "@/components/ui"
import type { AgentStatus } from "@/lib/api"
import { count, timeAgo } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

export default function AgentsPage() {
  const { data, error, refresh } = usePoll<{ results: AgentStatus[] }>("/agents", 6000)
  const defensive = data?.results.filter((a) => a.pipeline_position !== null).sort((a, b) => (a.pipeline_position ?? 0) - (b.pipeline_position ?? 0)) ?? []
  const attacker = data?.results.find((a) => a.name === "attacker_agent")
  return (
    <>
      <PageHeader
        title="Agents"
        description="Four defensive agents run in order through a LangGraph pipeline; the Attacker Agent sits outside it and only feeds simulated telemetry in."
      />
      {error && <ErrorState error={error} onRetry={refresh} />}
      {!data ? <Panel><Loading rows={6} /></Panel> : (
        <div className="space-y-5">
          <ol className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {defensive.map((a, i) => <AgentCard key={a.name} agent={a} step={i + 1} />)}
          </ol>
          {attacker && (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <AgentCard agent={attacker} />
              <Panel title="How the agents talk" className="md:col-span-1 xl:col-span-3">
                <ul className="space-y-2 text-[13.5px] text-muted">
                  <li><span className="text-text">State, not HTTP.</span> Agents share one LangGraph state object; each adds its own section (behavior, risk, response) and a timing record.</li>
                  <li><span className="text-text">Tools through MCP.</span> Agents read baselines, incident history, rule explanations, policy and the knowledge base through allow-listed, read-only MCP tools.</li>
                  <li><span className="text-text">LLM is optional.</span> Each agent has a deterministic fallback, so the pipeline keeps working when the model is offline.</li>
                  <li><span className="text-text">Simulations are honest.</span> The Attacker Agent attaches ground truth; models never see it, so detections are real.</li>
                </ul>
              </Panel>
            </div>
          )}
        </div>
      )}
    </>
  )
}

function AgentCard({ agent: a, step }: { agent: AgentStatus; step?: number }) {
  return (
    <li className="list-none">
      <Link href={`/agents/${a.name}`} className="block h-full rounded-[var(--radius-panel)] border border-line bg-panel p-4 hover:border-line-strong">
        <div className="flex items-center justify-between">
          <span className="text-[13px] text-faint">{step ? `Stage ${step}` : "Outside the pipeline"}</span>
          <StatusDot status={a.status} />
        </div>
        <h2 className="mt-1 font-display text-[20px] font-semibold">{a.title}</h2>
        <p className="text-[13.5px] text-muted">{a.role}</p>
        <p className="mt-3 text-[12.5px] text-faint">{a.input} in, {a.output.toLowerCase()} out</p>
        <dl className="mt-4 grid grid-cols-3 gap-2 border-t border-line pt-3 text-[13px]">
          <div><dt className="text-muted">Runs 24 h</dt><dd className="text-[16px] font-medium">{count(a.processed)}</dd></div>
          <div><dt className="text-muted">Latency</dt><dd className="text-[16px] font-medium">{Math.round(a.avg_latency_ms)} ms</dd></div>
          <div><dt className="text-muted">Errors</dt><dd className={`text-[16px] font-medium ${a.errors ? "text-[var(--color-sev-high)]" : ""}`}>{a.errors}</dd></div>
        </dl>
        <p className="mt-3 line-clamp-2 text-[13px] text-muted">{a.last_summary || "No activity yet"}</p>
        <p className="mt-1 text-[12px] text-faint">{timeAgo(a.last_activity)}, LLM {a.llm_feature_enabled ? "on" : "off"}</p>
      </Link>
    </li>
  )
}
