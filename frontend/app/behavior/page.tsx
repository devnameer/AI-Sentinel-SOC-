"use client"

import { Search } from "lucide-react"
import { useState, type FormEvent } from "react"
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"

import {
  Button, Chips, EmptyState, ErrorState, Loading, Mono, PageHeader, Panel, ScoreMeter, SeverityBadge,
} from "@/components/ui"
import { post, query, type BehaviorDetails, type RiskLevel } from "@/lib/api"
import { count, dateTime, humanize, score, timeAgo } from "@/lib/format"
import { usePoll } from "@/lib/use-poll"

interface UserRow { user_id: string; analyses: number; flagged: number; max_score: number | null; last_seen: string }
interface UserDetail {
  user_id: string
  baseline: Record<string, unknown> | null
  history: { id: string; created_at: string; score: number | null; risk_level: RiskLevel | ""; flagged: boolean; rules: string[]; dimension_scores: Record<string, number> }[]
}

export default function BehaviorPage() {
  const [q, setQ] = useState("")
  const [search, setSearch] = useState("")
  const [user, setUser] = useState<string>()
  const users = usePoll<{ results: UserRow[]; baseline_users: number }>(`/behavior/users${query({ q: search })}`, 10000)
  const active = user ?? users.data?.results[0]?.user_id

  return (
    <>
      <PageHeader
        title="Behavior analysis"
        description="Each user is compared with their own baseline: usual login hours, devices, file volume and sensitivity."
      />
      <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
        <Panel title="Users" aside={users.data && <span className="text-[13px]">{count(users.data.baseline_users)} baselines</span>} bodyClassName="p-0">
          <form className="flex gap-2 border-b border-line p-3" onSubmit={(e) => { e.preventDefault(); setSearch(q) }}>
            <label className="sr-only" htmlFor="user-search">Search users</label>
            <input id="user-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="User ID, e.g. AAM0658"
              className="h-9 min-w-0 flex-1 rounded-md border border-line-strong bg-raised px-2 text-[14px]" />
            <Button type="submit" aria-label="Search" icon={<Search size={15} />} />
          </form>
          {users.error && <div className="p-3"><ErrorState error={users.error} /></div>}
          {!users.data ? <div className="p-3"><Loading /></div> : users.data.results.length === 0 ? (
            <p className="p-4 text-faint">No analysed users yet{search ? " for this search" : ""}.</p>
          ) : (
            <ul className="max-h-[560px] overflow-y-auto">
              {users.data.results.map((u) => (
                <li key={u.user_id}>
                  <button onClick={() => setUser(u.user_id)} aria-current={active === u.user_id}
                    className={`flex w-full items-center justify-between gap-3 border-b border-line/60 px-4 py-2.5 text-left hover:bg-raised/50 ${active === u.user_id ? "bg-raised" : ""}`}>
                    <span>
                      <Mono>{u.user_id}</Mono>
                      <span className="block text-[12px] text-muted">{u.analyses} sessions, {u.flagged} flagged, {timeAgo(u.last_seen)}</span>
                    </span>
                    <span className="text-[13px] text-muted">{score(u.max_score)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="min-w-0 space-y-5">
          {active ? <UserProfile userId={active} /> : <EmptyState title="Pick a user">Users appear here once their sessions have been analysed.</EmptyState>}
          <TrySession defaultUser={active ?? "AAM0658"} />
        </div>
      </div>
    </>
  )
}

function UserProfile({ userId }: { userId: string }) {
  const { data, error } = usePoll<UserDetail>(`/behavior/users/${encodeURIComponent(userId)}`, 10000)
  if (error) return <ErrorState error={error} />
  if (!data) return <Panel><Loading rows={5} /></Panel>
  const b = data.baseline
  const history = [...data.history].reverse().map((h, i) => ({ ...h, n: i + 1 }))
  const latest = data.history[0]
  return (
    <Panel title={<span>Baseline for <Mono className="text-[14px]">{userId}</Mono></span>}
      aside={b && <span className="text-[13px]">{b.cold_start ? "Cold start (new user)" : `${b.observation_days} days observed`}</span>}>
      {b && (
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-[13.5px] md:grid-cols-4">
          <div><dt className="text-muted">Department</dt><dd>{String(b.department)}</dd></div>
          <div><dt className="text-muted">Usual login hour</dt><dd>{Number(b.login_hour_mean).toFixed(1)} h ± {Number(b.login_hour_std).toFixed(1)}</dd></div>
          <div><dt className="text-muted">Files per day</dt><dd>{Number(b.daily_file_access_mean).toFixed(1)}</dd></div>
          <div><dt className="text-muted">Department USB rate</dt><dd>{Math.round(Number(b.dept_usb_rate) * 100)}% of sessions</dd></div>
          <div className="col-span-2"><dt className="text-muted">Known devices</dt><dd><Chips items={(b.known_devices as string[]) ?? []} /></dd></div>
          <div className="col-span-2"><dt className="text-muted">Sensitivity (typical / role ceiling)</dt><dd>{String(b.typical_max_sensitivity)} / {String(b.role_sensitivity_ceiling)}</dd></div>
        </dl>
      )}
      <div className="mt-5">
        <p className="mb-2 text-[13px] text-muted">Anomaly score per analysed session (oldest to newest); the dashed line is the flag threshold.</p>
        {history.length ? (
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history} margin={{ top: 6, right: 8, bottom: 0, left: -20 }}>
                <CartesianGrid stroke="var(--color-line)" strokeOpacity={0.6} vertical={false} />
                <XAxis dataKey="n" stroke="var(--color-line)" tick={{ fill: "var(--color-muted)", fontSize: 12 }} tickLine={false} />
                <YAxis domain={[0, 1]} stroke="var(--color-line)" tick={{ fill: "var(--color-muted)", fontSize: 12 }} tickLine={false} axisLine={false} />
                <ReferenceLine y={0.4} stroke="var(--color-muted)" strokeDasharray="4 4" />
                <Tooltip contentStyle={{ background: "var(--color-raised)", border: "1px solid var(--color-line-strong)", borderRadius: 6, color: "var(--color-text)" }}
                  formatter={(v: unknown) => [Number(v).toFixed(3), "Anomaly score"]} labelFormatter={(n: unknown) => `Session ${String(n)}`} />
                <Line dataKey="score" stroke="var(--color-series-1)" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : <p className="text-faint">No sessions analysed for this user yet.</p>}
      </div>
      {latest && (
        <div className="mt-5 grid gap-5 md:grid-cols-2">
          <div>
            <p className="mb-2 text-[13px] text-muted">Latest session ({dateTime(latest.created_at)}) deviation by dimension</p>
            <div className="space-y-2">
              {Object.entries(latest.dimension_scores).map(([k, v]) => (
                <div key={k} className="grid grid-cols-[90px_1fr] items-center gap-3 text-[13px]"><span>{humanize(k)}</span><ScoreMeter value={v} /></div>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-2 text-[13px] text-muted">Signals in the latest session</p>
            <Chips items={latest.rules} empty="No rule fired" />
          </div>
        </div>
      )}
    </Panel>
  )
}

const FIELDS: { key: string; label: string }[] = [
  { key: "usb_connected", label: "USB device connected" },
  { key: "usb_first_time", label: "First USB use ever" },
  { key: "visited_exfil_domain", label: "Visited a leak / file-sharing site" },
  { key: "visited_jobsearch_domain", label: "Visited a job-search site" },
  { key: "has_ext_email", label: "E-mailed an external address" },
]

function TrySession({ defaultUser }: { defaultUser: string }) {
  const [form, setForm] = useState<Record<string, string | number | boolean>>({ hour_of_day: 2, file_count: 40, pc: "", usb_connected: true, usb_first_time: true })
  const [userOverride, setUserOverride] = useState<string>()
  const [result, setResult] = useState<BehaviorDetails & { triggered_rules?: string[]; flagged?: boolean; explanation?: string }>()
  const [error, setError] = useState<Error>()
  const [busy, setBusy] = useState(false)
  const userId = userOverride ?? defaultUser

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      const body = {
        user_id: userId, pc: form.pc || undefined, hour_of_day: Number(form.hour_of_day), file_count: Number(form.file_count),
        is_outside_hours: Number(form.hour_of_day) < 8 || Number(form.hour_of_day) >= 18 ? 1 : 0,
        ...Object.fromEntries(FIELDS.map((f) => [f.key, form[f.key] ? 1 : 0])),
      }
      const res = await post<{ behavior: typeof result }>("/behavior/analyze", body)
      setResult(res.behavior)
    } catch (err) {
      setError(err as Error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel title="Test a session against a baseline" aside={<span className="text-[13px]">dry run, nothing is stored</span>}>
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-[1fr_1fr]">
        <div className="grid grid-cols-2 gap-3 text-[13px] text-muted">
          <label className="col-span-2 flex flex-col gap-1">User ID
            <input value={userId} onChange={(e) => setUserOverride(e.target.value)} className="h-9 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text" />
          </label>
          <label className="flex flex-col gap-1">Login hour (0–23)
            <input type="number" min={0} max={23} value={Number(form.hour_of_day)} onChange={(e) => setForm({ ...form, hour_of_day: e.target.value })}
              className="h-9 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text" />
          </label>
          <label className="flex flex-col gap-1">Files accessed
            <input type="number" min={0} value={Number(form.file_count)} onChange={(e) => setForm({ ...form, file_count: e.target.value })}
              className="h-9 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text" />
          </label>
          <label className="col-span-2 flex flex-col gap-1">Workstation (empty = user&apos;s own)
            <input value={String(form.pc)} onChange={(e) => setForm({ ...form, pc: e.target.value })} placeholder="PC-1234"
              className="h-9 rounded-md border border-line-strong bg-raised px-2 text-[14px] text-text" />
          </label>
        </div>
        <fieldset className="space-y-2 text-[13.5px]">
          <legend className="mb-1 text-[13px] text-muted">Activity in the session</legend>
          {FIELDS.map((f) => (
            <label key={f.key} className="flex items-center gap-2">
              <input type="checkbox" checked={Boolean(form[f.key])} onChange={(e) => setForm({ ...form, [f.key]: e.target.checked })} className="size-4 accent-[var(--color-accent)]" />
              {f.label}
            </label>
          ))}
          <Button type="submit" variant="primary" busy={busy} className="mt-2">Score session</Button>
        </fieldset>
      </form>
      {error && <div className="mt-4"><ErrorState error={error} /></div>}
      {result && (
        <div className="mt-5 rounded-md border border-line bg-raised/50 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge level={result.verdict === "LOW" ? "LOW" : result.verdict === "MEDIUM" ? "MEDIUM" : "HIGH"} score={result.score} />
            <span className="text-[13px] text-muted">
              Isolation Forest {score(result.if_score)}, rules {score(result.rule_score)}, {result.flagged ? "flagged" : "not flagged"} at threshold {result.threshold}
            </span>
          </div>
          <div className="mt-3"><Chips items={result.triggered_rules ?? []} empty="No rule fired" /></div>
          {result.explanation && <p className="mt-3 text-[13.5px] text-muted">{result.explanation}</p>}
        </div>
      )}
    </Panel>
  )
}
