"use client"

import { HardDrive, Pause, Play } from "lucide-react"
import { useState } from "react"

import { AnalysisDrawer } from "@/components/analysis-drawer"
import { Button, EmptyState, ErrorState, Loading, Mono, PageHeader, Panel, Select, SeverityBadge } from "@/components/ui"
import { post, query, type Page, type SocEvent } from "@/lib/api"
import { clock, count, EXECUTION_LABEL, humanize } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

const SINCE: Record<string, number | null> = { "15m": 15, "1h": 60, "24h": 1440, all: null }

function describe(e: SocEvent): string {
  const m = e.metadata as Record<string, unknown>
  if (e.event_type === "user_session") {
    const signals = (m.signals as string[] | undefined) ?? []
    return `${m.file_count ?? 0} files, ${m.email_count ?? 0} e-mails${signals.length ? `, ${signals.map(humanize).join(", ").toLowerCase()}` : ""}`
  }
  if (e.event_type === "network_connection") {
    return `${m.protocol ?? ""} ${m.src_ip ?? "?"} to ${m.dst_ip ?? "?"}:${m.dst_port ?? ""}`
  }
  return e.resource
}

export default function EventsPage() {
  const [severity, setSeverity] = useState("")
  const [source, setSource] = useState("")
  const [eventType, setEventType] = useState("")
  const [status, setStatus] = useState("")
  const [since, setSince] = useState("24h")
  const [paused, setPaused] = useState(false)
  const [selected, setSelected] = useState<string>()
  const [busy, setBusy] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<string>()
  const [actionError, setActionError] = useState<Error>()

  const path = `/events${query({ severity, source, event_type: eventType, status, since_minutes: SINCE[since], limit: 100 })}`
  const events = usePoll<Page<SocEvent>>(path, paused ? 0 : 4000)

  async function ingest(src: "replay" | "host") {
    setBusy(src)
    setActionError(undefined)
    setActionMsg(undefined)
    try {
      const res = await post<{ analyses: unknown[]; collection?: { collectors: string[] } }>(
        "/events/ingest", src === "replay" ? { source: "replay", count: 5 } : { source: "host" })
      setActionMsg(src === "host"
        ? `Collected from this host with ${res.collection?.collectors.join(", ")}; ${res.analyses.length} analyses created.`
        : `${res.analyses.length} sessions replayed through the pipeline.`)
      await events.refresh()
    } catch (e) {
      setActionError(e as Error)
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <PageHeader
        title="Live security events"
        description="Raw telemetry as the Data Agent received it. Severity is assigned after the pipeline scores the event."
        actions={
          <>
            <Button onClick={() => ingest("replay")} busy={busy === "replay"} icon={<Play size={15} aria-hidden />}>Replay 5 sessions</Button>
            <Button onClick={() => ingest("host")} busy={busy === "host"} icon={<HardDrive size={15} aria-hidden />}
              title="Runs the read-only collectors enabled in config.yaml on the machine hosting the backend">
              Collect from this host
            </Button>
          </>
        }
      />
      {actionMsg && <p className="mb-4 rounded-md border border-line bg-panel px-4 py-2 text-[13.5px]" role="status">{actionMsg}</p>}
      {actionError && <div className="mb-4"><ErrorState error={actionError} /></div>}

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <Select label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
        </Select>
        <Select label="Source" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option>
          <option value="replay">Dataset replay</option>
          <option value="attacker_agent">Attacker Agent</option>
          <option value="psutil,os_scan,browser_history,windows_eventlog">Host collectors</option>
          <option value="manual">Manual</option>
        </Select>
        <Select label="Event type" value={eventType} onChange={(e) => setEventType(e.target.value)}>
          <option value="">All types</option>
          {["user_session", "logon", "file_access", "device_connect", "http_request", "email_sent", "network_connection", "process_start"].map((t) => (
            <option key={t} value={t}>{humanize(t)}</option>
          ))}
        </Select>
        <Select label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any status</option>
          {Object.entries(EXECUTION_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </Select>
        <Select label="Time" value={since} onChange={(e) => setSince(e.target.value)}>
          <option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="all">All time</option>
        </Select>
        <Button variant="ghost" className="self-end" onClick={() => setPaused((p) => !p)} icon={paused ? <Play size={15} /> : <Pause size={15} />}>
          {paused ? "Resume updates" : "Pause updates"}
        </Button>
      </div>

      {events.error && <div className="mb-4"><ErrorState error={events.error} onRetry={events.refresh} /></div>}

      <Panel bodyClassName="p-0" title="Events" aside={<span className="text-[13px]">{events.data ? `${count(events.data.count)} matching` : ""}</span>}>
        {!events.data ? (
          <div className="p-4"><Loading rows={6} /></div>
        ) : events.data.results.length === 0 ? (
          <div className="p-4">
            <EmptyState title="No events match these filters">
              Widen the time window, or replay sessions to generate activity.
            </EmptyState>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-[13.5px]">
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-normal">Severity</th>
                  <th className="px-2 py-2 font-normal">Time</th>
                  <th className="px-2 py-2 font-normal">Type</th>
                  <th className="px-2 py-2 font-normal">User / host</th>
                  <th className="px-2 py-2 font-normal">Detail</th>
                  <th className="px-4 py-2 font-normal">Source</th>
                </tr>
              </thead>
              <tbody>
                {events.data.results.map((e) => (
                  <tr
                    key={e.id}
                    tabIndex={e.analysis_id ? 0 : -1}
                    onClick={() => e.analysis_id && setSelected(e.analysis_id)}
                    onKeyDown={(k) => k.key === "Enter" && e.analysis_id && setSelected(e.analysis_id)}
                    className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-raised/50 focus-visible:bg-raised"
                  >
                    <td className="px-4 py-2"><SeverityBadge level={e.severity} /></td>
                    <td className="px-2 py-2 text-muted">{clock(e.timestamp)}</td>
                    <td className="px-2 py-2">{humanize(e.event_type)}</td>
                    <td className="px-2 py-2"><Mono>{e.user_id}</Mono> <span className="text-muted">@ <Mono>{e.device_id}</Mono></span></td>
                    <td className="max-w-[340px] truncate px-2 py-2 text-muted" title={describe(e)}>{describe(e)}</td>
                    <td className="px-4 py-2 text-muted">
                      {e.is_simulated ? <span className="text-[var(--color-series-2)]">Simulation</span> : humanize(e.source)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {selected && <AnalysisDrawer id={selected} onClose={() => setSelected(undefined)} onChanged={events.refresh} />}
    </>
  )
}
