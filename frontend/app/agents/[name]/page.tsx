"use client"

import { ChevronLeft } from "lucide-react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { ErrorState, FigureStrip, Loading, PageHeader, Panel, StatusDot } from "@/components/ui"
import type { AgentDetail } from "@/lib/api"
import { clock, count, timeAgo } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

export default function AgentDetailPage() {
  const { name } = useParams<{ name: string }>()
  const { data: a, error, refresh } = usePoll<AgentDetail>(`/agents/${encodeURIComponent(name)}`, 6000)
  const [selected, setSelected] = useState<string>()
  const llmRuns = a?.recent_runs.filter((r) => r.details.llm) ?? []
  const llmOk = llmRuns.filter((r) => r.details.llm?.ok).length
  return (
    <>
      <Link href="/agents" className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-text"><ChevronLeft size={15} aria-hidden /> All agents</Link>
      {error && <ErrorState error={error} onRetry={refresh} />}
      {!a ? <Panel><Loading rows={6} /></Panel> : (
        <>
          <PageHeader title={a.title} description={a.role} actions={<StatusDot status={a.status} />} />
          <FigureStrip items={[
            { label: "Runs in 24 h", value: count(a.processed) },
            { label: "Average latency", value: `${Math.round(a.avg_latency_ms)} ms` },
            { label: "Errors", value: a.errors },
            { label: "Last activity", value: timeAgo(a.last_activity) },
            { label: "LLM feature", value: a.llm_feature_enabled ? "On" : "Off", hint: llmRuns.length ? `${llmOk}/${llmRuns.length} recent calls answered` : "no recent calls" },
            { label: "Enabled", value: a.enabled ? "Yes" : "No", hint: "agents.*.enabled in config.yaml" },
          ]} />
          {a.last_error && <div className="mt-4"><ErrorState error={new Error(`Last error: ${a.last_error}`)} /></div>}
          <Panel title="Recent runs" className="mt-5" bodyClassName="p-0">
            {a.recent_runs.length === 0 ? <p className="p-4 text-faint">This agent has not run yet.</p> : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-[13.5px]">
                  <thead className="text-[12px] text-muted">
                    <tr className="border-b border-line">
                      <th className="px-4 py-2 font-normal">Time</th><th className="px-2 py-2 font-normal">Status</th>
                      <th className="px-2 py-2 text-right font-normal">Duration</th><th className="px-2 py-2 font-normal">Decision / output</th>
                      <th className="px-4 py-2 font-normal">Tools and LLM</th>
                    </tr>
                  </thead>
                  <tbody>
                    {a.recent_runs.map((r) => (
                      <tr key={r.id} className={`border-b border-line/60 last:border-0 ${r.analysis_id ? "cursor-pointer hover:bg-raised/50" : ""}`}
                        onClick={() => r.analysis_id && setSelected(r.analysis_id)}>
                        <td className="px-4 py-2 text-muted">{clock(r.started_at)}</td>
                        <td className="px-2 py-2"><StatusDot status={r.status === "ok" ? "online" : r.status} label={r.status} /></td>
                        <td className="px-2 py-2 text-right">{r.duration_ms.toFixed(0)} ms</td>
                        <td className="max-w-[360px] truncate px-2 py-2" title={r.error || r.summary}>{r.error || r.summary}</td>
                        <td className="px-4 py-2 text-[12.5px] text-muted">
                          {(r.details.tool_calls ?? []).map((t) => t.tool).join(", ") || "—"}
                          {r.details.llm && <span className="block">{r.details.llm.provider} {r.details.llm.ok ? `${r.details.llm.latency_ms} ms` : "failed, fallback used"}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} />}
    </>
  )
}
