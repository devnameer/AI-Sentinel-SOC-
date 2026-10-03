"use client"

import { useState, type FormEvent } from "react"

import { Button, ErrorState, Loading, Mono, PageHeader, Panel, Select, StatusDot } from "@/components/ui"
import { patch, type PublicConfig } from "@/lib/api"
import { humanize } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

const PROVIDERS: { value: string; label: string; note: string }[] = [
  { value: "ollama", label: "Ollama (local)", note: "Free, runs on your machine" },
  { value: "groq", label: "Groq", note: "Free tier with rate limits, needs GROQ_API_KEY" },
  { value: "huggingface", label: "Hugging Face router", note: "Needs HF_TOKEN, free credits are limited" },
  { value: "openai_compatible", label: "OpenAI-compatible server", note: "LM Studio, vLLM, llama.cpp…" },
  { value: "mock", label: "Mock (testing)", note: "Deterministic canned answers" },
  { value: "none", label: "Off", note: "Agents use templates and policy only" },
]

function Flag({ on }: { on: boolean }) {
  return <StatusDot status={on ? "enabled" : "disabled"} label={on ? "On" : "Off"} />
}

export default function SettingsPage() {
  const { data: cfg, error, refresh } = usePoll<PublicConfig>("/config")
  const [provider, setProvider] = useState<string>()
  const [model, setModel] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string>()
  const [saveError, setSaveError] = useState<Error>()

  const currentProvider = provider ?? cfg?.llm.provider ?? "ollama"
  const currentModel = model ?? cfg?.llm.providers[currentProvider]?.model ?? ""

  async function save(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setMsg(undefined)
    setSaveError(undefined)
    try {
      const res = await patch<{ note: string }>("/config", { llm_provider: currentProvider, ...(currentModel && cfg?.llm.providers[currentProvider] ? { llm_model: currentModel } : {}) })
      setMsg(`Switched to ${currentProvider}. ${res.note}`)
      await refresh()
    } catch (err) {
      setSaveError(err as Error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader title="Settings" description={<>Configuration lives in <Mono>backend/config/config.yaml</Mono> (settings) and <Mono>.env</Mono> (secrets). This page shows it and lets you switch the LLM for the current run.</>} />
      {error && <ErrorState error={error} onRetry={refresh} />}
      {!cfg ? (!error && <Panel><Loading rows={8} /></Panel>) : (
        <div className="grid gap-5 xl:grid-cols-2">
          <Panel title="Language model">
            <form onSubmit={save} className="space-y-4">
              <div className="flex flex-wrap items-end gap-3">
                <Select label="Provider" value={currentProvider} onChange={(e) => { setProvider(e.target.value); setModel(undefined) }}>
                  {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                </Select>
                {cfg.llm.providers[currentProvider] && (
                  <label className="flex flex-col gap-1 text-[13px] text-muted">Model
                    <input value={currentModel} onChange={(e) => setModel(e.target.value)} className="h-9 w-56 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text" />
                  </label>
                )}
                <Button type="submit" variant="primary" busy={busy}>Switch provider</Button>
              </div>
              <p className="text-[13px] text-muted">{PROVIDERS.find((p) => p.value === currentProvider)?.note}. The switch lasts until the backend restarts; set <Mono>LLM_PROVIDER</Mono> in .env to make it permanent.</p>
              {msg && <p role="status" className="rounded-md bg-raised px-3 py-2 text-[13.5px]">{msg}</p>}
              {saveError && <ErrorState error={saveError} />}
            </form>
            <dl className="mt-5 grid grid-cols-2 gap-y-2 border-t border-line pt-4 text-[13.5px]">
              {Object.entries(cfg.llm.features).map(([k, v]) => (
                <div key={k} className="contents"><dt className="text-muted">{humanize(k)}</dt><dd><Flag on={v} /></dd></div>
              ))}
              <dt className="text-muted">Only for flagged events</dt><dd><Flag on={cfg.llm.only_for_flagged_events} /></dd>
              <dt className="text-muted">Fallback provider</dt><dd>{cfg.llm.fallback_provider}</dd>
              <dt className="text-muted">Timeout</dt><dd>{cfg.llm.timeout_seconds} s</dd>
            </dl>
          </Panel>

          <Panel title="Secrets (.env)">
            <p className="mb-3 text-[13.5px] text-muted">Only whether each value is set is shown. Values never leave the backend.</p>
            <ul className="space-y-2 text-[13.5px]">
              {Object.entries(cfg.secrets_configured).map(([k, v]) => (
                <li key={k} className="flex justify-between"><Mono>{k}</Mono><StatusDot status={v ? "enabled" : "idle"} label={v ? "Set" : "Not set"} /></li>
              ))}
            </ul>
          </Panel>

          <Panel title="Agents">
            <ul className="space-y-2 text-[13.5px]">
              {Object.entries(cfg.agents).map(([name, a]) => (
                <li key={name} className="flex justify-between"><span>{humanize(name)}</span><Flag on={Boolean(a.enabled)} /></li>
              ))}
            </ul>
          </Panel>

          <Panel title="Detection and response policy">
            <dl className="grid grid-cols-2 gap-y-2 text-[13.5px]">
              <dt className="text-muted">Behaviour scoring</dt><dd>{String(cfg.ml.behavior?.scoring_mode)}</dd>
              <dt className="text-muted">Anomaly threshold</dt><dd>{String(cfg.ml.behavior?.anomaly_threshold)}</dd>
              <dt className="text-muted">Risk bands</dt><dd>low &lt; {cfg.risk.thresholds.low_max}, medium ≤ {cfg.risk.thresholds.medium_max}, high above</dd>
              <dt className="text-muted">Approval required for</dt><dd>{cfg.response.require_approval_for.map((l) => humanize(l.toLowerCase())).join(", ")}</dd>
              <dt className="text-muted">Auto-execute high risk</dt><dd><Flag on={cfg.response.auto_execute_high_risk} /></dd>
              <dt className="text-muted">MCP transport</dt><dd>{cfg.mcp.transport}</dd>
              <dt className="text-muted">Database</dt><dd>{cfg.database.engine}</dd>
              <dt className="text-muted">Retrieval</dt><dd>{String(cfg.retrieval.backend)} ({String(cfg.retrieval.embedding_model).split("/").pop()})</dd>
            </dl>
            <p className="mt-4 text-[12.5px] text-faint">To clear demo data run <Mono>python manage.py reset_demo</Mono> in the backend folder.</p>
          </Panel>
        </div>
      )}
    </>
  )
}
