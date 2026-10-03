"use client"

import { Pause, Play } from "lucide-react"
import { useState } from "react"

import { Button, ErrorState, Loading, PageHeader, Panel, Select, cx } from "@/components/ui"
import { query, type LogRecord } from "@/lib/api"
import { clock } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

const LEVEL_TONE: Record<string, string> = {
  DEBUG: "text-faint", INFO: "text-muted", WARNING: "text-[var(--color-sev-medium)]",
  ERROR: "text-[var(--color-sev-high)]", CRITICAL: "text-[var(--color-sev-high)]",
}

export default function LogsPage() {
  const [level, setLevel] = useState("INFO")
  const [logger, setLogger] = useState("")
  const [paused, setPaused] = useState(false)
  const { data, error, refresh } = usePoll<{ results: LogRecord[] }>(`/system/logs${query({ level, logger, limit: 400 })}`, paused ? 0 : 3000)
  const rows = [...(data?.results ?? [])].reverse()
  return (
    <>
      <PageHeader title="Logs" description="The most recent backend log records (kept in memory, newest first). Structured fields are shown after each message." />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <Select label="Minimum level" value={level} onChange={(e) => setLevel(e.target.value)}>
          {["DEBUG", "INFO", "WARNING", "ERROR"].map((l) => <option key={l} value={l}>{l.charAt(0) + l.slice(1).toLowerCase()}</option>)}
        </Select>
        <Select label="Component" value={logger} onChange={(e) => setLogger(e.target.value)}>
          <option value="">Everything</option>
          <option value="soc.agents">Agents</option>
          <option value="soc.llm">LLM</option>
          <option value="soc.mcp">MCP tools</option>
          <option value="soc.ml">Models</option>
          <option value="soc.rag">Knowledge base</option>
          <option value="soc.services">Services</option>
          <option value="django">Django</option>
        </Select>
        <Button variant="ghost" className="self-end" onClick={() => setPaused((p) => !p)} icon={paused ? <Play size={15} /> : <Pause size={15} />}>
          {paused ? "Resume" : "Pause"}
        </Button>
      </div>
      {error && <ErrorState error={error} onRetry={refresh} />}
      <Panel bodyClassName="p-0">
        {!data ? <div className="p-4"><Loading rows={8} /></div> : rows.length === 0 ? <p className="p-4 text-faint">No log records at this level yet.</p> : (
          <ol className="max-h-[70vh] overflow-y-auto font-mono text-[12.5px]">
            {rows.map((r) => (
              <li key={r.id} className="grid grid-cols-[72px_70px_1fr] gap-3 border-b border-line/50 px-4 py-1.5 last:border-0 md:grid-cols-[72px_70px_170px_1fr]">
                <span className="text-faint">{clock(r.timestamp)}</span>
                <span className={cx(LEVEL_TONE[r.level])}>{r.level.toLowerCase()}</span>
                <span className="truncate text-muted max-md:hidden">{r.logger}</span>
                <span className="min-w-0 break-words">
                  {r.message}
                  {r.context && <span className="text-faint"> {Object.entries(r.context).map(([k, v]) => `${k}=${String(v)}`).join(" ")}</span>}
                  {r.exception && <span className="block text-[var(--color-sev-high)]">{r.exception}</span>}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </>
  )
}
