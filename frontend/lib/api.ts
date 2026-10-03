/**
 * Typed client for the Django API.
 *
 * The browser never talks to Django directly: every call goes to the Next.js
 * route /api/soc/... which forwards it server-side and adds the API token
 * (see app/api/soc/[...path]/route.ts). No secret reaches the browser.
 */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH"
export type Action = "ALLOW" | "MONITOR" | "ESCALATE" | "BLOCK"

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message)
  }
}

export interface SocEvent {
  id: string
  timestamp: string
  ingested_at: string
  source: string
  event_type: string
  category: string
  user_id: string
  device_id: string
  resource: string
  metadata: Record<string, unknown>
  is_simulated: boolean
  severity: RiskLevel | ""
  analysis_id: string | null
}

export interface IncidentBrief {
  id: number
  reference: string
  status: IncidentStatus
  severity: RiskLevel
  recommended_action: Action
  final_action: Action | ""
}

export interface Analysis {
  id: string
  created_at: string
  source: string
  kind: "behavior" | "network"
  user_id: string
  device_id: string
  score: number | null
  flagged: boolean
  verdict: string
  model: string
  triggered_rules: string[]
  threat_category: string
  mitre_techniques: string[]
  explanation: string
  explanation_source: "llm" | "template" | ""
  risk_score: number | null
  risk_level: RiskLevel | ""
  decision: Action | ""
  action: Action | ""
  execution: string
  is_simulated: boolean
  ground_truth: boolean | null
  status: "ok" | "error"
  errors: string[]
  incident: IncidentBrief | null
  simulation_id: string | null
}

export interface AgentRun {
  id: number
  agent: string
  started_at: string
  duration_ms: number
  status: "ok" | "error" | "skipped"
  summary: string
  error: string
  analysis_id: string | null
  details: { tool_calls?: { tool: string; ok: boolean; ms: number; transport: string }[]; llm?: LlmMeta | null }
}

export interface LlmMeta {
  ok: boolean
  provider: string
  model: string
  latency_ms: number
  error: string | null
}

export interface BehaviorDetails {
  score: number
  if_score?: number
  rule_score?: number
  threshold: number
  verdict: string
  scoring_mode?: string
  dimension_scores?: Record<string, number>
  rule_explanations?: Record<string, string>
  knowledge?: { source: string; title: string }[]
  baseline?: Record<string, unknown>
  baseline_update?: string
  confidence?: string
  cold_start?: boolean
  network?: Record<string, unknown>
  llm?: LlmMeta | null
}

export interface RiskDetails {
  base_score: number
  llm_adjustment: number
  repeat_offender_penalty: number
  risk_score: number
  risk_level: RiskLevel
  decision: Action
  recommended_action: string
  risk_factors: string[]
  mitigating_factors: string[]
  reasoning: string
  method: string
  llm?: LlmMeta | null
}

export interface ResponseDetails {
  action: Action
  execution: string
  requires_approval: boolean
  policy: {
    action: Action
    recommended_action: Action
    state: string
    source: string
    visits: number
    q_values: Record<Action, number>
    guardrail: string | null
  }
  summary: string
  summary_source: string
  playbook: string[]
}

export interface AnalysisDetail extends Analysis {
  details: {
    behavior?: BehaviorDetails
    risk?: RiskDetails
    response?: ResponseDetails
    session?: Record<string, unknown>
  }
  events: SocEvent[]
  runs: AgentRun[]
}

export type IncidentStatus = "awaiting_approval" | "auto_executed" | "approved" | "denied" | "resolved"

export interface Incident {
  id: number
  reference: string
  created_at: string
  updated_at: string
  title: string
  severity: RiskLevel
  status: IncidentStatus
  recommended_action: Action
  final_action: Action | ""
  decided_at: string | null
  decided_by: string
  decision_note: string
  notification: Record<string, unknown>
  analysis: Analysis
}

export interface Page<T> {
  count: number
  limit: number
  offset: number
  results: T[]
}

export interface Overview {
  window_hours: number
  totals: {
    events: number
    analyses: number
    suspicious: number
    active_threats: number
    blocked: number
    escalated: number
    incidents_open: number
    simulations: number
    avg_anomaly_score: number
    avg_risk_score: number
  }
  risk_distribution: Record<RiskLevel, number>
  executions: Record<string, number>
  response_actions: Record<Action, number>
  threat_categories: Record<string, number>
  timeline: { hour: string; analyses: number; flagged: number; high: number; events: number }[]
  score_histogram: { bucket: string; count: number }[]
  simulation_outcomes: Record<string, number>
}

export interface AgentStatus {
  name: string
  title: string
  role: string
  input: string
  output: string
  enabled: boolean
  status: "active" | "idle" | "error" | "disabled"
  llm_feature_enabled: boolean
  processed: number
  errors: number
  avg_latency_ms: number
  last_activity: string | null
  last_summary: string
  last_error: string
  pipeline_position: number | null
}

export interface AgentDetail extends AgentStatus {
  recent_runs: AgentRun[]
}

export interface Scenario {
  id: string
  name: string
  kind: "behavior" | "network"
  tactic: string
  technique: string
  severity: string
  malicious: boolean
  description: string
  cert_scenario: number | null
  targets: string[]
}

export interface Simulation {
  id: string
  created_at: string
  scenario_id: string
  name: string
  kind: string
  technique: string
  tactic: string
  target: string
  device: string
  expected_malicious: boolean
  status: "running" | "detected" | "missed" | "correctly_ignored" | "false_positive" | "error"
  planner: { method?: string; reasoning?: string }
  error: string
  analysis: {
    id: string
    score: number | null
    flagged: boolean
    risk_level: RiskLevel | ""
    risk_score: number | null
    action: Action | ""
    execution: string
    triggered_rules: string[]
    explanation: string
    incident_id: number | null
  } | null
}

export interface ProviderHealth {
  provider: string
  model: string
  status: "online" | "offline" | "misconfigured" | "disabled"
  detail: string
  hint: string
  models_available: string[]
}

export interface Health {
  status: "healthy" | "degraded" | "unhealthy"
  warnings: string[]
  environment: { app_env: string; python: string; platform: string; auth_enabled: boolean }
  components: {
    database: { status: string; engine: string; error?: string }
    llm: {
      status: string
      provider: string
      model: string | null
      fallback_provider: string
      calls: number
      failures: number
      fallback_used: number
      primary: ProviderHealth
      fallback: ProviderHealth | null
    }
    behavior_model: { status: string; error: string | null; warnings: string[]; path: string; features: number; scoring_mode: string; threshold: number; estimators: number | null }
    network_model: { status: string; errors: Record<string, string>; components: Record<string, boolean>; threshold: number }
    baselines: { status: string; users?: number; error?: string }
    rl_policy: { status: string; states: number; trained_states: number; updates: number; metadata: Record<string, unknown> }
    retrieval: { status: string; backend?: string | null; chunks?: number; error?: string | null; embedding_model?: string | null }
    replay_dataset: { status: string; sessions?: number; insider_sessions?: number; users?: number; position?: number; error?: string }
    mcp: { status: string; transport: string }
    twilio: { status: string; configured: boolean }
    stream: StreamStatus
  }
}

export interface StreamStatus {
  status: "running" | "stopped"
  source: string
  interval_seconds: number
  batch_size: number
  batches: number
  started_at: string | null
  last_error: string
}

export interface LogRecord {
  id: number
  timestamp: string
  level: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL"
  logger: string
  message: string
  context?: Record<string, unknown>
  exception?: string
}

export interface EvaluationMetrics {
  roc_auc: number
  average_precision: number
  threshold: number
  flag_rate: number
  session_precision: number
  session_recall: number
  malicious_users_flagged: string
  benign_users_flagged: string
}

export interface Evaluation {
  sessions: number
  insider_sessions: number
  isolation_forest: EvaluationMetrics
  rules_only: EvaluationMetrics
  hybrid: EvaluationMetrics
  config: { if_weight: number; rules_weight: number }
  computed_at: string
}

export interface PolicyRow {
  state: string
  visits: number
  best_action: Action
  q_values: Record<Action, number>
}

export interface PolicyResponse {
  stats: {
    states: number
    trained_states: number
    updates: number
    hyperparameters: { alpha: number; gamma: number; epsilon: number }
    greedy_action_distribution: Record<Action, number>
    metadata: Record<string, unknown>
  }
  table: PolicyRow[]
}

export interface PublicConfig {
  app: { name: string; environment: string }
  llm: {
    provider: string
    fallback_provider: string
    temperature: number
    max_tokens: number
    timeout_seconds: number
    only_for_flagged_events: boolean
    providers: Record<string, { base_url: string; model: string }>
    features: Record<string, boolean>
  }
  agents: Record<string, Record<string, unknown>>
  ml: Record<string, Record<string, unknown>>
  risk: { thresholds: { low_max: number; medium_max: number }; min_action: Record<string, string>; max_action: Record<string, string> }
  response: { require_approval_for: RiskLevel[]; auto_execute_high_risk: boolean }
  retrieval: Record<string, unknown>
  mcp: { transport: string }
  database: { engine: string }
  secrets_configured: Record<string, boolean>
}

const BASE = "/api/soc"

export async function api<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init ?? {}
  const res = await fetch(`${BASE}${path}`, {
    ...rest,
    headers: { "Content-Type": "application/json", ...(rest.headers ?? {}) },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    cache: "no-store",
  })
  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    body = null
  }
  if (!res.ok) {
    const err = (body as ApiErrorBody | null)?.error
    throw new ApiError(
      res.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed with status ${res.status}`,
      err?.details,
    )
  }
  return body as T
}

export const post = <T>(path: string, json: unknown = {}) => api<T>(path, { method: "POST", json })
export const patch = <T>(path: string, json: unknown = {}) => api<T>(path, { method: "PATCH", json })

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v))
  }
  const s = q.toString()
  return s ? `?${s}` : ""
}
