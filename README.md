# Sentinel SOC — Multi-Agent Cybersecurity Platform

An AI-assisted **Security Operations Center (SOC)** you can run on your own laptop, for free.
Five cooperating agents collect security telemetry, detect anomalous behaviour with machine learning,
score the risk, and recommend a response that a human analyst approves or denies on a web dashboard.
A sixth component, the **Attacker Agent**, plays known attack scenarios against the pipeline so you can
measure, not assume, what gets detected.

The language model runs **locally through Ollama** by default. No paid API is needed for any feature.

> University project, built for learning and demonstration. It is **not** a production security
> product, and it never touches real systems: containment actions are recorded, not executed.

---

## Contents

1. [Key features](#key-features)
2. [Architecture](#architecture)
3. [Technology stack](#technology-stack)
4. [Cost: what is free and what is optional](#cost-what-is-free-and-what-is-optional)
5. [Quick start (local development)](#quick-start-local-development)
6. [Ollama and model installation](#ollama-and-model-installation)
7. [Configuration](#configuration)
8. [LLM providers](#llm-providers)
9. [Running with Docker](#running-with-docker)
10. [Using the dashboard](#using-the-dashboard)
11. [Agent architecture](#agent-architecture)
12. [Attack simulation](#attack-simulation)
13. [ML models](#ml-models)
14. [Reinforcement learning (Q-learning)](#reinforcement-learning-q-learning)
15. [RAG / retrieval](#rag--retrieval)
16. [MCP tools](#mcp-tools)
17. [Human-in-the-loop response](#human-in-the-loop-response)
18. [API documentation](#api-documentation)
19. [Testing](#testing)
20. [Troubleshooting](#troubleshooting)
21. [Security considerations](#security-considerations)
22. [Project structure](#project-structure)
23. [Limitations and future improvements](#limitations-and-future-improvements)
24. [License](#license)

---

## Key features

- **Five-agent pipeline orchestrated with LangGraph**: Data → Behavior → Risk & Decision → Response,
  plus an Attacker Agent that feeds simulated attacks into the same pipeline.
- **Real ML detection**: an Isolation Forest + rule hybrid for insider threats (trained on the CERT r4.2
  insider-threat dataset, scored against per-user baselines) and an Isolation Forest + CatBoost network model.
- **Local LLM reasoning (Ollama)** for analyst-style explanations, bounded risk adjustments and incident
  playbooks. Every LLM feature has a deterministic fallback, so the platform still works with the LLM off.
- **Provider-agnostic LLM layer**: switch between Ollama, Groq, Hugging Face or any OpenAI-compatible
  server by changing one line. Agents never change.
- **Q-learning response policy** that is pre-trained from ground truth and keeps learning from the
  analyst's APPROVE / DENY decisions, with hard guardrails so it can never under-react to high risk.
- **Human-in-the-loop**: medium and high risk findings become incidents that wait for an analyst decision
  in the dashboard. Twilio SMS alerts are optional.
- **RAG knowledge base** (MITRE ATT&CK techniques, detection rules, risk policy, response playbooks) with
  local Sentence-Transformers + FAISS embeddings, or a TF-IDF fallback that needs no download.
- **MCP tool server**: agents use read-only, allow-listed tools through the Model Context Protocol. The
  same server can be opened from any MCP client.
- **Modern SOC dashboard** (Next.js, TypeScript, Tailwind, Recharts): overview, live events, detections,
  behaviour analysis, risk decisions, agent telemetry, attack simulation, incidents, system health, logs
  and settings.
- **Honest numbers**: every figure on the dashboard comes from recorded pipeline runs. Simulated events
  are labelled as simulated, and model evaluation reports precision as well as recall.

---

## Architecture

```mermaid
flowchart TD
    UI["Next.js SOC Dashboard<br/>(browser)"]
    PROXY["Next.js server proxy<br/>/api/soc/* (adds API token)"]
    API["Django REST API<br/>/api/v1"]
    LG["LangGraph pipeline"]
    DA[Data Agent]
    BA[Behavior Agent]
    RA[Risk & Decision Agent]
    RS[Response Agent]
    ATK["Attacker Agent<br/>(simulation only)"]
    ML["ML models<br/>Isolation Forest · CatBoost · rules"]
    RL["Q-learning policy"]
    LLM["LLM layer<br/>Ollama (default) · Groq · HF · OpenAI-compatible"]
    MCP["MCP tool server<br/>read-only tools"]
    RAG["Knowledge base<br/>Sentence-Transformers + FAISS / TF-IDF"]
    DB[("SQLite (default)<br/>or PostgreSQL")]
    HUMAN(("Analyst<br/>APPROVE / DENY"))

    UI --> PROXY --> API
    API --> LG
    ATK -->|simulated telemetry| LG
    LG --> DA --> BA --> RA --> RS
    BA --> ML
    RS --> RL
    BA & RA & RS --> LLM
    DA & BA & RA & RS --> MCP
    MCP --> RAG
    MCP --> DB
    API --> DB
    RS -->|incident| UI
    UI --> HUMAN -->|decision = RL reward| API
```

**How one event flows** (this is what happens when you click *Replay 10 sessions* or *Run* on an attack):

```text
Data Agent      normalise raw events → one user session, or a window of network connections
    ↓
Behavior Agent  ML anomaly score + triggered rules + MITRE mapping (+ LLM explanation)
    ↓
Risk Agent      base score + bounded LLM adjustment + repeat-offender penalty → LOW / MEDIUM / HIGH
    ↓
Response Agent  Q-learning action (ALLOW / MONITOR / ESCALATE / BLOCK) → guardrails
    ↓
LOW → logged automatically          MEDIUM / HIGH → incident waiting for APPROVE / DENY
```

Each agent run is stored with its latency, status, tool calls and LLM usage. The *Agents* page shows that
telemetry, not invented numbers.

---

## Technology stack

| Layer | Technology | Why it is here |
|---|---|---|
| Frontend | Next.js 16, React 19, TypeScript | Dashboard and a server-side API proxy |
| | Tailwind CSS 4, Lucide icons, Recharts | Styling, icons, charts |
| Backend | Python 3.11+, Django 5, Django REST Framework | REST API, validation, persistence |
| | django-cors-headers | Allows direct browser calls during development |
| | pydantic, PyYAML, python-dotenv | Validated central configuration (`config.yaml` + `.env`) |
| Agents | LangGraph | Orchestrates the four defensive agents as a state graph |
| | MCP (Model Context Protocol) | Tool interface between agents and data/knowledge |
| LLM | Ollama (default), httpx | Local inference; httpx talks to every provider without vendor SDKs |
| ML | scikit-learn, CatBoost, NumPy, pandas, joblib | Isolation Forest, CatBoost, features, evaluation |
| RL | Plain Python (JSON Q-table) | Small, explainable tabular Q-learning |
| Retrieval | Sentence-Transformers + FAISS (optional), scikit-learn TF-IDF (fallback) | Local RAG |
| Data | SQLite (default), PostgreSQL (optional) | Events, analyses, incidents, agent runs |
| Host telemetry | psutil (+ pywin32 on Windows, optional) | Read-only host collectors |
| Ops | Docker, Docker Compose, gunicorn | Containerised run |
| Tests | pytest, pytest-django | 86 automated tests, mock LLM, no network |

---

## Cost: what is free and what is optional

**The core project runs without any paid API.** Everything marked *Required* below is free and local.

| Resource | Purpose | Cost | Required? |
|---|---|---|---|
| Python, Django, DRF, Next.js, React, TypeScript, Tailwind | Application | Free (open source) | Required |
| LangGraph, MCP SDK | Agent orchestration, tool protocol | Free (open source) | Required |
| scikit-learn, CatBoost, NumPy, pandas | ML | Free (open source) | Required (CatBoost optional at runtime) |
| SQLite | Database | Free, built into Python | Required (default) |
| Q-learning | Response policy | Free (own code) | Required |
| **Ollama** + open models (Qwen, Llama, Gemma) | Local LLM | **Free, local** | Recommended (the platform also runs with the LLM off) |
| Sentence-Transformers, FAISS | Dense RAG embeddings | Free, local (one ~90 MB model download from Hugging Face) | Optional (TF-IDF fallback) |
| Hugging Face Hub | Downloading open models / embeddings | Free | Optional |
| PostgreSQL | Database | Free (self-hosted) | Optional |
| Groq API | Hosted LLM fallback | **Free tier with rate limits** (requests/tokens per minute and per day) | Optional |
| Hugging Face Inference Providers | Hosted LLM | **Small monthly free credit, then pay-as-you-go** | Optional |
| Supabase (hosted PostgreSQL) | Hosted database | **Free tier with limits**, paid above | Optional |
| Twilio SMS | Phone alerts for pending approvals | **Paid** (trial credit available) | Optional, off by default |
| Cloud hosting | Running it on a server | Varies (free tiers exist, all with limits) | Optional |

Free tiers and prices change. Check each provider's current pricing page before relying on one.

---

## Quick start (local development)

You need **Python 3.11 or newer**, **Node.js 20.9 or newer**, and about 2 GB of free disk space
(plus 2–6 GB for a local model).

### 1. Get the code and create `.env`

```bash
git clone <your-repo-url> sentinel-soc
cd sentinel-soc
cp .env.example .env          # Windows (PowerShell): Copy-Item .env.example .env
```

An empty `.env` is fine for local use. See [Configuration](#configuration) for what each variable does.

### 2. Backend (Django + agents)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate     # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate      # creates data/runtime/soc.sqlite3
python manage.py check_config # validates config.yaml and checks every model/dataset file
python manage.py runserver    # http://localhost:8000/api/v1/
```

Optional extras (dense RAG embeddings, PostgreSQL driver, Twilio, Windows collectors):

```bash
pip install -r requirements-optional.txt
```

### 3. Frontend (Next.js dashboard), in a second terminal

```bash
cd frontend
npm install
npm run dev                   # http://localhost:3000
```

Open **http://localhost:3000**. The dashboard talks to Django through its own server-side proxy, so the
browser never needs to reach port 8000 directly.

### 4. LLM (in a third terminal, or the Ollama desktop app)

```bash
ollama pull qwen3:8b
ollama serve                  # not needed if the Ollama app is already running
```

Without Ollama the platform still works: the dashboard shows **LLM: offline** with the hint
`Start Ollama with: ollama serve`, and the agents fall back to rule-based reasoning and templates.

### 5. Try it

1. On **Overview**, click **Replay 10 sessions**. Ten real CERT r4.2 sessions run through all agents.
2. Open **Attack simulation** and run *After-hours USB exfiltration to WikiLeaks*.
3. Open **Incidents** and **Approve** or **Deny** the recommended action. That decision becomes the
   reward for the Q-learning policy.
4. Click **Start live replay** (top right) for a continuous stream of sessions during a demo.

To clear all demo data: `cd backend && python manage.py reset_demo`.

---

## Ollama and model installation

1. Install Ollama from **https://ollama.com/download** (Windows, macOS, Linux).
   On Linux: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull a model that fits your machine:

| Your machine | Suggested model | Command | Approx. download |
|---|---|---|---|
| 16 GB RAM or a GPU with ≥ 8 GB VRAM | `qwen3:8b` (default) | `ollama pull qwen3:8b` | ~5 GB |
| 8 GB RAM, no GPU | `qwen3:4b` | `ollama pull qwen3:4b` | ~2.5 GB |
| Older / low-memory laptop | `llama3.2:3b` or `gemma3:4b` | `ollama pull llama3.2:3b` | ~2–3 GB |

3. Tell the platform which model to use, either in `.env`:

```env
LLM_PROVIDER=ollama
LLM_MODEL=qwen3:4b
OLLAMA_BASE_URL=http://localhost:11434
```

or in `backend/config/config.yaml` under `llm.providers.ollama.model`. You can also switch model for the
current run on the **Settings** page.

**You do not need a 70B model.** The LLM writes short explanations and makes small, bounded adjustments;
all detection is done by the ML models. A 4B–8B model is enough. On CPU-only machines each LLM call can take
10–60 s, so `llm.only_for_flagged_events: true` (the default) skips the LLM for normal sessions.

---

## Configuration

There is exactly **one settings file** and **one secrets file**:

| File | Contains | Committed to git? |
|---|---|---|
| `backend/config/config.yaml` | Every non-secret setting: LLM provider and model, agents on/off, ML thresholds, risk bands, RL hyper-parameters, RAG, MCP, database engine | Yes |
| `.env` (repository root) | Secrets and machine-specific values: API keys, tokens, database URL, Django secret key | **No**, only `.env.example` is |

The YAML is validated with pydantic at start-up, so a typo like `provider: olama` stops the backend with a
clear message instead of failing later. Check it any time with `python manage.py check_config`.

A few YAML keys can be overridden from `.env` for convenience (marked `[env: NAME]` in the YAML):
`LLM_PROVIDER`, `LLM_FALLBACK_PROVIDER`, `LLM_MODEL`, `OLLAMA_BASE_URL`, `GROQ_MODEL`, `HF_MODEL`,
`OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_MODEL`, `EMBEDDING_MODEL`, `APP_ENV`.

### Environment variables

Everything is optional for local development.

| Variable | Used for | When you need it |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django cryptographic signing | **Required when `APP_ENV=production`**; otherwise a random key is generated per run |
| `APP_ENV` | `development` or `production` (stricter settings, JSON logs) | Deployments |
| `DJANGO_DEBUG` | Django debug pages | Debugging only, never in production |
| `DJANGO_ALLOWED_HOSTS` | Host names Django answers to | Serving on another host name |
| `CORS_ALLOWED_ORIGINS` | Origins allowed to call the API from a browser directly | Rarely: the dashboard uses its proxy |
| `SOC_API_TOKEN` | Bearer token required on every API call | **Recommended** whenever the API is reachable by other machines |
| `BACKEND_URL` | Where the Next.js server finds Django | Non-default ports; Docker sets it |
| `LLM_PROVIDER`, `LLM_FALLBACK_PROVIDER` | Choose the LLM provider and an optional fallback | Switching provider |
| `OLLAMA_BASE_URL`, `LLM_MODEL` | Ollama address and model | Non-default Ollama setup or model |
| `GROQ_API_KEY`, `GROQ_MODEL` | Groq provider | Only if you use Groq |
| `HF_TOKEN`, `HF_MODEL` | Hugging Face provider; also used for model downloads | Only if you use HF inference or gated models |
| `OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_MODEL`, `LLM_API_KEY` | LM Studio / vLLM / llama.cpp server | Only for that provider |
| `EMBEDDING_MODEL` | Sentence-Transformers model for RAG | Changing the embedding model |
| `DATABASE_URL`, `DATABASE_SSLMODE` | PostgreSQL connection | Only with `database.engine: postgres` |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, `TWILIO_TO_NUMBER` | SMS alerts | Only with `notifications.twilio.enabled: true` |
| `LOG_LEVEL`, `LOG_JSON` | Logging verbosity and format | Optional |
| `SOC_CONFIG_PATH` | Use a different YAML file | Advanced |
| `DOCKER_OLLAMA_URL` | Ollama address seen from inside Docker | Docker only (default `http://host.docker.internal:11434`) |

### Switching to PostgreSQL (optional)

```bash
pip install -r backend/requirements-optional.txt        # installs psycopg
```

```yaml
# backend/config/config.yaml
database:
  engine: postgres
```

```env
# .env
DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/sentinel
DATABASE_SSLMODE=prefer        # "require" for hosted Postgres such as Supabase
```

Then run `python manage.py migrate` again.

---

## LLM providers

```text
Application (agents)
      ↓
core/llm.py  — LLMClient.chat() / chat_json()
      ↓  provider chosen in config.yaml / .env
┌───────────────────────────┬──────────────────────────────┬────────────────────────────┐
│ ollama                    │ groq                         │ huggingface / openai_compat │
│ local, free — PRIMARY     │ free tier — OPTIONAL fallback│ OPTIONAL                    │
└───────────────────────────┴──────────────────────────────┴────────────────────────────┘
      + mock  (deterministic labelled answers for tests)      + none  (LLM switched off)
```

| Provider | `LLM_PROVIDER` | Needs | Notes |
|---|---|---|---|
| Ollama | `ollama` | `ollama serve` + a pulled model | **Default.** Free, private, offline |
| Groq | `groq` | `GROQ_API_KEY` | Free tier with rate limits; fast hosted Llama/Qwen models |
| Hugging Face | `huggingface` | `HF_TOKEN` | HF Inference Providers router (OpenAI-compatible); small free credit |
| OpenAI-compatible | `openai_compatible` | Server URL (+ `LLM_API_KEY` if required) | LM Studio, vLLM, llama.cpp server, … |
| Mock | `mock` | Nothing | Answers are prefixed `[mock LLM]` so they are never mistaken for real output |
| None | `none` | Nothing | All LLM features off; agents use rules and templates |

**Ollama only (default, nothing paid):**

```env
LLM_PROVIDER=ollama
LLM_MODEL=qwen3:8b
```

**Ollama with Groq as automatic fallback** (used only when an Ollama call fails):

```env
LLM_PROVIDER=ollama
LLM_FALLBACK_PROVIDER=groq
GROQ_API_KEY=your-key-from-console.groq.com
GROQ_MODEL=llama-3.1-8b-instant
```

**Groq only** (no local model):

```env
LLM_PROVIDER=groq
GROQ_API_KEY=your-key-from-console.groq.com
```

Groq's model list changes over time; if a model is retired, pick a current one from the Groq console and
set `GROQ_MODEL`.

What makes the layer robust:

- Agents receive an `LLMResult` with `ok=True/False` and always have a fallback path, so a stopped Ollama,
  a missing key or a rate limit never crashes the pipeline.
- After a failure the provider is skipped for `retry_cooldown_seconds` (30 s), so the dashboard does not wait
  for a timeout on every event.
- Timeouts are configurable (`llm.timeout_seconds`).
- `<think>…</think>` blocks from reasoning models (Qwen3, DeepSeek-R1) are stripped; JSON answers wrapped in
  code fences or prose are still parsed.
- The **System health** and **Settings** pages show the provider status with a fix-it hint, for example
  `Ollama: offline — Start Ollama with: ollama serve` or `Model 'qwen3:8b' is not pulled — ollama pull qwen3:8b`.

What the LLM is used for (each switchable in `llm.features`):

| Feature | Agent | Default | Without LLM |
|---|---|---|---|
| `behavior_explanation` | Behavior | on | Template built from the model output |
| `risk_assessment` | Risk | on | Policy-only decision (labelled `method: policy`) |
| `response_summary` | Response | on | Template summary + playbook from a lookup table |
| `data_tool_selection` | Data | off | Collectors from `config.yaml` |
| `attack_planning` | Attacker | off | Least-tested scenario first |

The LLM **never** sets the anomaly score. In the Risk Agent it can only move the score by at most
`±max_llm_adjustment` (0.3) and must list its risk and mitigating factors.

---

## Running with Docker

Requires Docker with Compose v2.24 or newer.

```bash
cp .env.example .env            # optional, but recommended
docker compose up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:8000/api/v1/

**Ollama on the host (recommended, simplest GPU setup).** Start Ollama on your machine as usual; the
backend container reaches it at `host.docker.internal:11434`.

**Ollama in Docker too:**

```bash
docker compose --profile ollama up --build -d
docker compose exec ollama ollama pull qwen3:8b
```

and add `DOCKER_OLLAMA_URL=http://ollama:11434` to `.env`, then `docker compose up -d` again.
For an NVIDIA GPU, uncomment the `deploy:` block in `docker-compose.yml` (needs the NVIDIA Container Toolkit).

Runtime data (SQLite database, learned baselines, learned Q-table, RAG index) lives in the `soc-runtime`
volume. `docker compose down -v` deletes it.

Useful commands:

```bash
docker compose logs -f backend
docker compose exec backend python manage.py check_config
docker compose exec backend python manage.py reset_demo --yes
```

The backend container runs gunicorn with **one worker and eight threads** on purpose: models, the Q-table,
the live-replay thread and the runtime LLM switch are held in process memory.

---

## Using the dashboard

| Page | What it shows |
|---|---|
| **Overview** | Signal path through the four agents, totals (events, suspicious sessions, awaiting approval, blocked, mean anomaly score), threats over time, risk distribution, recent decisions, attack types, response actions, anomaly-score histogram, simulation scorecard, detection stack and LLM status |
| **Live events** | Event table with filters for severity, source (agent), event type, status and time window; replay or collect from this host |
| **Threat detection** | All analyses (sessions and network windows) with risk, category, MITRE technique and action, plus the on-demand model evaluation table |
| **Behavior analysis** | Users ranked by flagged sessions, per-user baseline and score history |
| **Risk & decisions** | Base score → LLM adjustment → repeat-offender penalty → final level, and the learned Q-table |
| **Agents** / agent detail | Live status, runs, latency, errors, tool calls, LLM success rate and recent runs per agent |
| **Attack simulation** | Scenario catalogue, run any scenario against a chosen target, detection scorecard and history |
| **Incidents** | Medium/high risk findings with **Approve** / **Deny** and the full reasoning chain |
| **System health** | Database, LLM provider, models, baselines, RL policy, RAG, MCP, Twilio, warnings with fixes |
| **Logs** | Structured backend logs, filterable by level and component |
| **Settings** | Effective configuration, which secrets are set (never their values), runtime LLM switch |

Clicking any row opens a drawer with the complete chain: raw events → features → model scores → rules →
LLM note → risk computation → Q-values → final action.

---

## Agent architecture

All defensive agents subclass `agents/base.py::BaseAgent`, which makes each one a LangGraph node, times it,
catches errors (a failing agent halts the run with a readable message instead of an HTTP 500) and records a
trace. They share one typed state, `agents/state.py::SOCState`.

```text
START ─► data_agent ─► behavior_agent ─► risk_agent ─► response_agent ─► END
              │               │
              └─── halted ────┴─────────────────────────────────────────► END
```

| Agent | File | Input → output | Uses |
|---|---|---|---|
| **Data Agent** | `agents/data_agent.py` | Raw events (CERT replay, host collectors, attacker, manual) → one user *session* or a *network window* | MCP `collect_host_events`, optional LLM collector choice |
| **Behavior Agent** | `agents/behavior_agent.py` | Session / window → anomaly score, verdict, triggered rules, MITRE techniques, explanation | Behaviour or network model, baselines, MCP `explain_rules` + `search_knowledge`, LLM note |
| **Risk & Decision Agent** | `agents/risk_agent.py` | Behaviour result → risk score, LOW/MEDIUM/HIGH, decision, risk/mitigating factors | MCP `get_risk_policy`, `get_user_incident_history`, `search_knowledge`, bounded LLM adjustment |
| **Response Agent** | `agents/response_agent.py` | Risk assessment → action, execution mode, summary, playbook | Q-learning policy + guardrails, RAG playbooks, LLM summary |
| **Attacker Agent** | `agents/attacker_agent.py` | Scenario → simulated telemetry with ground truth | Baselines of real CERT insiders; optional LLM planning |

The Attacker Agent is deliberately **outside** the defensive graph: like a real adversary, it only produces
input. Every agent can be switched off in `config.yaml › agents.<name>.enabled`.

---

## Attack simulation

The Attacker Agent **fabricates log events only**. It never executes code, scans hosts or sends packets.

| Scenario | Kind | MITRE | Ground truth |
|---|---|---|---|
| After-hours USB exfiltration to WikiLeaks (CERT scenario 1) | Insider | T1052.001 | Malicious |
| Job hunting followed by USB data theft (CERT scenario 2) | Insider | T1052.001 | Malicious |
| Keylogger + supervisor impersonation (CERT scenario 3) | Insider | T1056.001 | Malicious |
| Bulk download of sensitive files | Insider | T1005 | Malicious |
| Normal working day (control) | Insider | — | **Benign**, measures false positives |
| DNS reflection amplification | Network | T1498.002 | Malicious |
| TCP SYN flood | Network | T1498.001 | Malicious |
| Network service discovery (port scan) | Network | T1046 | Malicious |

Insider scenarios are generated **relative to the target user's real baseline** (their usual hours, file
volume and devices), so detection depends on genuine deviation. The result is classified as `detected`,
`missed`, `correctly_ignored` or `false_positive`, and missed attacks are shown, not hidden. Simulations never
update a real user's baseline.

From the dashboard: **Attack simulation → Run** (or **Let the attacker choose**). From the API:

```bash
curl -X POST http://localhost:8000/api/v1/attacks/simulate/ \
     -H "Content-Type: application/json" \
     -d '{"scenario_id": "usb_exfil_wikileaks"}'
```

---

## ML models

All ML code lives in `backend/ml/`, split by responsibility:

| File | Responsibility |
|---|---|
| `datasets.py` | Loading the CERT sessions, insider labels, replay iterator (data preprocessing) |
| `features.py` | Session normalisation, 18 baseline-relative features, rules, network features (feature engineering) |
| `baselines.py` | Per-user behavioural baselines in SQLite, score-gated updates |
| `behavior_model.py` | Insider-threat inference (Isolation Forest + rules) |
| `network_model.py` | Network inference (Isolation Forest + CatBoost + verification rules) |
| `evaluation.py` | Metrics on the labelled sessions (model evaluation) |
| `q_learning.py` | Response policy (see next section) |
| `scripts/train_*.py` | Training (never at API start-up) |

Models are **loaded lazily on first use and never trained when the API starts**. Paths are configurable in
`config.yaml › ml`; a missing file produces a clear error on the health page instead of a crash.

```text
models/
├── behavior/   isolation_forest.joblib, feature_columns.json, score_bounds.json
├── network/    isolation_forest.joblib, catboost.cbm, minmax_scaler.joblib
└── rl/         q_table.json            (pre-trained policy, JSON, read-only at runtime)
data/
├── datasets/   cert_r42_sessions.csv.gz, cert_insiders.csv, cert_r42_baselines.sqlite
└── runtime/    created automatically: soc.sqlite3, baselines.sqlite, q_table.json, rag_index/
```

### Insider-threat (behaviour) model

- **Data**: 133,270 user-day sessions from the public **CERT r4.2** insider-threat dataset (Carnegie Mellon
  SEI), 616 of them inside a known insider's malicious window.
- **Features**: 18 features measured against each user's own baseline (log-on time deviation, file volume
  z-score, sensitivity above the user's usual level, USB use, unknown device, external e-mail, exfiltration
  and job-search domains, …).
- **Scoring**: `hybrid = 0.4 × Isolation Forest + 0.6 × rule score` (weights in `config.yaml`); sessions
  with a score ≥ 0.4 are flagged. `scoring_mode: isolation_forest` reproduces the original IF-only behaviour.
- **Baselines** update only from sessions that scored below `baseline_update_threshold`, so an attacker
  cannot slowly "teach" the model that exfiltration is normal.

Evaluation on the labelled CERT sessions (`python scripts/evaluate_behavior_model.py`, threshold 0.4):

| Mode | ROC-AUC | Avg. precision | Session recall | Session precision | Malicious users flagged | Benign users flagged |
|---|---|---|---|---|---|---|
| Isolation Forest only | 0.710 | 0.010 | 0.53 | 0.012 | 48 / 49 | 281 / 497 |
| Rules only | 0.718 | 0.114 | 0.39 | 0.013 | 45 / 49 | 164 / 497 |
| **Hybrid (default)** | **0.734** | 0.056 | **0.55** | **0.016** | 45 / 49 | **201 / 497** |

Read these honestly: only 0.46 % of sessions are malicious, so **most flags are false positives**. That is
typical for unsupervised insider-threat detection and is exactly why the platform puts a human in the loop.
The original project reported only "malicious users flagged", which looks much better than session precision.
The same table is available on the **Threat detection** page and at `GET /api/v1/ml/evaluation/`.

The shipped Isolation Forest was trained with scikit-learn 1.6.1. Newer versions load it with a warning.
To retrain it with your installed version (time-based split, insider windows excluded from training):

```bash
python scripts/train_behavior_model.py             # writes models/behavior_retrained/
```

then point the three `ml.behavior.*_path` keys at the new files.

### Network model

Two-stage model from the original project, trained on **UNSW-NB15**: an Isolation Forest anomaly score and
a CatBoost attack probability (`0.4 × IF + 0.6 × CatBoost`). Deterministic verification rules confirm or
reject model flags, and clear patterns (amplification, SYN flood, port scan) add a rule score. Without
CatBoost installed the model runs in IF-only mode and says so on the health page. Its training script was not
part of the original repository, so these artefacts are used as provided. Host snapshots from `psutil`
contain no byte counts, so they are scored by rules only rather than with made-up zeros.

---

## Reinforcement learning (Q-learning)

`backend/ml/q_learning.py` keeps every RL concept separate and readable:

| Concept | In this project |
|---|---|
| **State** | `risk_level | signal-count bucket | risk-score bucket | warm/cold baseline`, e.g. `HIGH|s4|r2|warm` |
| **Action** | `ALLOW`, `MONITOR`, `ESCALATE`, `BLOCK` |
| **Reward** | From ground truth during training (blocking an attack is good, blocking a benign user is bad), and from the analyst at runtime: APPROVE = +1, DENY = −1 |
| **Q-table** | JSON file, `state → {action: value}` (no pickle) |
| **Policy** | Greedy at inference, ε-greedy (ε = 0.1) while training; unseen states use a rule fallback, reported as such |
| **Update** | `Q(s,a) ← Q(s,a) + α · (r + γ · maxₐ' Q(s',a') − Q(s,a))`, α = 0.1 |

Each incident gets one decision that does not change the next incident, so every episode is one step
(a contextual bandit) and γ = 0 by default. **Guardrails** then clamp the learned action into the policy band
(HIGH risk ≥ ESCALATE, LOW risk ≤ MONITOR), so the policy can never under-react to high risk.

Pre-training (`python scripts/train_rl_policy.py`) uses 5,096 labelled samples (40,000 episodes) from
attacker simulations and CERT replay. On a held-out split the learned policy chooses a good action
**87.6 %** of the time versus **86.9 %** for the plain rule policy: a small gain, reported as it is.

The committed `models/rl/q_table.json` is only the starting point. Learning from analyst decisions is saved
to `data/runtime/q_table.json`, so demos never modify the repository; `reset_demo` returns to the pre-trained
policy.

---

## RAG / retrieval

```text
backend/rag/knowledge/*.md   (MITRE techniques, detection rules, risk policy, playbooks, CERT scenarios)
        ↓  chunked by heading
Sentence-Transformers (all-MiniLM-L6-v2, local)   — or TF-IDF if not installed
        ↓
FAISS index (cached in data/runtime/rag_index/)
        ↓  MCP tool: search_knowledge
Behavior / Risk / Response agents → grounded LLM prompts
```

- Default `retrieval.backend: auto` uses Sentence-Transformers + FAISS when
  `requirements-optional.txt` is installed, otherwise TF-IDF (no download, works offline).
- The embedding model is configurable (`EMBEDDING_MODEL`). It downloads once (~90 MB) from Hugging Face.
- The index is rebuilt automatically when a knowledge file changes. Test a query with
  `python scripts/build_rag_index.py "usb exfiltration after hours"`.
- To extend the knowledge base, add a Markdown file to `backend/rag/knowledge/`.

---

## MCP tools

`backend/tools/mcp_server.py` is a real MCP server (FastMCP). All tools are **read-only and allow-listed**:

| Tool | Purpose |
|---|---|
| `list_collectors` | Which host collectors exist and run on this OS |
| `collect_host_events` | Run allow-listed read-only collectors (system, process, network, file, …) |
| `get_user_baseline` | A user's behavioural baseline |
| `get_user_incident_history` | Recent medium/high findings for a user (repeat-offender rule) |
| `explain_rules` | Human-readable meaning of triggered detection rules |
| `search_knowledge` | RAG search over the knowledge base |
| `get_risk_policy` | Current risk thresholds and guardrails |

Agents call these through `tools/mcp_client.py`. `mcp.transport: inprocess` (default) calls the same tool
functions directly with schema validation; `mcp.transport: stdio` spawns the server and speaks the real MCP
protocol. You can also connect any MCP client (e.g. MCP Inspector) to it:

```bash
cd backend
python -m tools.mcp_server
```

Privacy-sensitive collectors (browser history, e-mail metadata) are off by default.

---

## Human-in-the-loop response

```text
Risk Agent ─► Response Agent ─► Incident (awaiting_approval) ─► Dashboard
                                                                  │
                                       HIGH RISK DETECTED         │
                                       Risk score: 91 %           │
                                       Threat: Data exfiltration  │
                                       User: CAH0936              │
                                       Recommended action: BLOCK  │
                                       [ APPROVE ]   [ DENY ]  ◄──┘
                                                │
                                Q-learning reward (+1 / −1), status recorded
```

| Risk level | Default behaviour (`config.yaml › response`) |
|---|---|
| LOW | Logged automatically |
| MEDIUM | Incident awaiting approval |
| HIGH | Incident awaiting approval (set `auto_execute_high_risk: true` to execute without waiting) |

"Executing" an action records it on the incident. **Nothing is done to real accounts, devices or
networks.** Optional Twilio SMS alerts for HIGH incidents: install `twilio`, set the four `TWILIO_*`
variables and `notifications.twilio.enabled: true`. The platform works fully without Twilio.

---

## API documentation

Base URL `http://localhost:8000/api/v1/`. JSON in and out. If `SOC_API_TOKEN` is set, send
`Authorization: Bearer <token>` (the dashboard does this for you). `GET /api/v1/` lists every endpoint.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/system/ping/` | Liveness probe (no auth) |
| GET | `/system/health/` | Health of every component, with fix hints |
| GET | `/system/logs/` | Recent structured logs (`level`, `logger`, `after`, `limit`) |
| GET, POST | `/system/stream/` | Live replay status / `{"action": "start" | "stop", "source": "replay"}` |
| GET | `/stats/overview/?hours=24` | Dashboard aggregates |
| GET, PATCH | `/config/` | Public configuration / runtime LLM switch `{"llm_provider": "groq", "llm_model": "..."}` |
| GET | `/events/` | Events, filters: `severity`, `source`, `event_type`, `user`, `status`, `simulated`, `since`, `since_minutes`, `limit`, `offset` |
| GET | `/events/live/?after=<iso>` | New events since a timestamp |
| POST | `/events/ingest/` | Run the pipeline: `{"source": "replay", "count": 5}`, `{"source": "host", "collectors": ["system"]}` or `{"source": "manual", "session": {...}}` |
| GET | `/analyses/`, `/analyses/<id>/` | Pipeline results / full reasoning chain |
| POST | `/behavior/analyze/` | Behavior Agent only, nothing stored |
| GET | `/behavior/users/`, `/behavior/users/<user_id>/` | Users ranked by risk / baseline and history |
| POST | `/risk/analyze/` | Risk Agent only, nothing stored |
| POST | `/response/decide/` | Response Agent only, nothing stored |
| GET | `/response/policy/` | Q-table statistics and rows |
| GET | `/agents/` (alias `/agents/status/`), `/agents/<name>/` | Agent status and recent runs |
| GET | `/attacks/` | Scenario catalogue, outcomes, simulation history |
| POST | `/attacks/simulate/` | `{"scenario_id": "...", "target_user": "...", "seed": 1}` (all optional) |
| GET | `/incidents/`, `/incidents/<id>/` | Incidents, filters: `status`, `severity` |
| POST | `/incidents/<id>/decision/` | `{"decision": "approve" | "deny", "note": "...", "analyst": "..."}` |
| GET | `/ml/evaluation/` | Model evaluation table (`?refresh=1` to recompute) |

Errors always have one shape, with a matching HTTP status (400 validation, 401 auth, 404 not found,
409 conflict, 429 throttled, 503 service unavailable):

```json
{"error": {"code": "validation_error", "message": "Request validation failed.", "details": {"count": ["..."]}}}
```

Examples:

```bash
curl http://localhost:8000/api/v1/system/health/
curl -X POST http://localhost:8000/api/v1/events/ingest/ -H "Content-Type: application/json" \
     -d '{"source": "replay", "count": 3}'
curl -X POST http://localhost:8000/api/v1/incidents/1/decision/ -H "Content-Type: application/json" \
     -d '{"decision": "approve", "note": "confirmed with manager"}'
```

---

## Testing

The test suite needs **no Ollama, no internet and no paid API**: it uses the mock LLM provider and isolates
every runtime file in a temporary folder.

```bash
cd backend
pip install -r requirements-dev.txt
pytest                                  # 86 tests
python -m compileall -q .               # syntax check
python manage.py check_config           # configuration validation
```

| File | Covers |
|---|---|
| `tests/test_config.py` | YAML validation, env overrides, secrets never exposed |
| `tests/test_llm.py` | Provider abstraction, Ollama offline, missing Groq key, fallback provider, cooldown, JSON parsing |
| `tests/test_agents.py` | Each agent, LangGraph pipeline, halting, LLM failure fallbacks, guardrails |
| `tests/test_ml.py` | Features, baselines, behaviour/network inference, Q-learning maths, seed vs runtime Q-table |
| `tests/test_mcp.py` | MCP tools, allow-list, in-process and stdio transports |
| `tests/test_api.py` | Every endpoint, validation errors, auth token, incident decisions, simulations |

**End-to-end smoke test** against running services (stdlib only):

```bash
python scripts/smoke_test.py                                    # backend → agents → ML → LLM → response
python scripts/smoke_test.py --frontend http://localhost:3000   # also through the Next.js proxy
```

Frontend checks:

```bash
cd frontend
npm run typecheck
npm run lint
npm run build
```

To check the optional Groq path, set `GROQ_API_KEY` and `LLM_PROVIDER=groq` in `.env`, restart the backend
and open **System health**: the LLM card should read `groq … online`.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Dashboard shows **LLM: offline** | Ollama is not running. Start it with `ollama serve` (or open the Ollama app). Everything else keeps working. |
| `Model 'qwen3:8b' is not pulled` | `ollama pull qwen3:8b`, or set `LLM_MODEL` to a model you have (`ollama list`). |
| LLM calls are very slow | CPU inference. Use a smaller model (`qwen3:4b`, `llama3.2:3b`), keep `only_for_flagged_events: true`, or raise `llm.timeout_seconds`. |
| `GROQ_API_KEY is not set in .env` | Add the key, or switch back to `LLM_PROVIDER=ollama`. |
| `groq rate limit reached` | Free-tier limit. Wait, or use Ollama as primary with Groq only as fallback. |
| Dashboard: *The backend is not reachable at http://localhost:8000* | Start Django (`cd backend && python manage.py runserver`) or set `BACKEND_URL`. |
| `no such table: api_event` | Run `python manage.py migrate` in `backend/`. |
| `Invalid configuration in config.yaml` | The message names the wrong key; fix it and run `python manage.py check_config`. |
| `DJANGO_SECRET_KEY must be set` | You set `APP_ENV=production`; add a secret key to `.env`. |
| 401 `Authentication required` | `SOC_API_TOKEN` is set: send `Authorization: Bearer <token>`, and make sure the frontend reads the same `.env`. |
| Health page: *Network model … IF-only* | CatBoost is not installed: `pip install catboost`. |
| Warning about scikit-learn versions | The shipped model was trained with 1.6.1. Harmless; retrain with `scripts/train_behavior_model.py` to remove it. |
| RAG backend shows `tfidf` | Normal without optional extras. For embeddings: `pip install -r requirements-optional.txt`. |
| Docker backend cannot reach Ollama | On Linux check that Ollama listens on all interfaces (`OLLAMA_HOST=0.0.0.0 ollama serve`), or use the `ollama` compose profile. |
| Start over with clean demo data | `python manage.py reset_demo` |

---

## Security considerations

This is a security project, so its own security matters. What is in place:

- **No secrets in code.** All credentials come from `.env`, which is git-ignored; only `.env.example` is
  committed. The Settings page shows whether a secret is set, never its value.
- **Optional API authentication** with a bearer token (`SOC_API_TOKEN`), compared in constant time. The
  Next.js server adds it, so the token never reaches the browser.
- **Safe Django defaults**: `DEBUG` off, explicit `ALLOWED_HOSTS` and CORS origins, `nosniff`,
  `X-Frame-Options: DENY`, strict referrer policy, required secret key in production.
- **No code execution tools.** The original project let the LLM run Python through a regex "sandbox"; that
  tool was removed. MCP tools are read-only and allow-listed, with bounded arguments.
- **Prompt-injection hygiene.** Collected data (file names, URLs, command lines) is attacker-controlled. It is
  wrapped in clearly delimited "untrusted data" blocks and truncated. More importantly, the LLM's power is
  bounded by design: it cannot change the ML score, can move the risk score by at most ±0.3, can only pick
  scenario IDs from a catalogue, and its output never triggers an action without guardrails and a human.
- **Input validation** on every endpoint (DRF serializers), ORM-only database access (no raw SQL), safe
  path-segment checks in the frontend proxy, rate limits on simulation and ingestion, and a single error
  format that never leaks stack traces.
- **Simulated attacker.** The Attacker Agent only writes synthetic log events. There is no exploit, scanner or
  network traffic generator.
- **Model files are JSON or joblib** produced by this project; never load model files from untrusted sources
  (joblib/pickle can execute code).

Known limitations, stated honestly:

- Without `SOC_API_TOKEN` the API is open. That is fine on `localhost`, not on a network.
- There are no user accounts or roles; anyone with dashboard access can approve incidents.
- Host collectors read local system information (processes, connections, recent files). Run them only on
  machines you are allowed to monitor.
- Prompt injection cannot be fully prevented with today's LLMs; the bounded design limits its impact.

### Note on the original repository

The original ZIP contained **real-looking credentials**: an LLM API key (in `README.md`,
`cybersec_frontend/env`, `data_agent/agents/config.json`, `data_agent/agents/llm_config.py` and
`RESPONSE_AGENT_INTEGRATION.md`), a hosted PostgreSQL (Supabase) connection URL **including its password**
(in `cybersec_frontend/env`), and a hard-coded Django `SECRET_KEY`. None of them are in this version.
**If that repository was ever public, revoke the API key, change the database password and treat the old
Django key as compromised**, because deleting a file does not remove it from git history.

---

## Project structure

```text
sentinel-soc/
├── .env.example                  template for secrets / machine settings (copy to .env)
├── .gitignore  .dockerignore
├── docker-compose.yml            backend + frontend (+ optional ollama profile)
├── README.md
│
├── backend/
│   ├── config/config.yaml        ← the ONE settings file
│   ├── core/                     config loader, LLM layer, auth, errors, logging
│   ├── agents/                   base, state, pipeline (LangGraph), 5 agents, shared resources
│   ├── ml/                       datasets, features, baselines, behaviour & network models, evaluation, Q-learning
│   ├── rag/                      retriever + knowledge/*.md
│   ├── tools/                    MCP server, MCP client, read-only host collectors
│   ├── api/                      models, serializers, views, services, health, live stream, management commands
│   ├── soc_platform/             Django settings / urls / wsgi
│   ├── tests/                    pytest suite (mock LLM, isolated runtime)
│   ├── manage.py  pytest.ini  Dockerfile
│   └── requirements.txt  requirements-optional.txt  requirements-dev.txt
│
├── frontend/
│   ├── app/                      pages (overview, events, detections, behavior, risk, agents, simulation,
│   │                             incidents, health, logs, settings) + api/soc proxy route
│   ├── components/               shell, UI kit, charts, pipeline, analysis drawer
│   ├── lib/                      typed API client, formatters, polling hook
│   ├── package.json  next.config.mjs  tsconfig.json  eslint.config.mjs  Dockerfile
│
├── models/                       trained artefacts (behavior/, network/, rl/)
├── data/
│   ├── datasets/                 CERT r4.2 sessions, insider labels, seed baselines
│   └── runtime/                  created at runtime (git-ignored)
└── scripts/                      train_behavior_model, evaluate_behavior_model, train_rl_policy,
                                  build_rag_index, smoke_test
```

---

## Limitations and future improvements

Limitations:

- The insider-threat detector has low session precision (see the evaluation table); it is a triage aid
  for a human, not an automatic blocker.
- The network model's features are approximated from simple connection records, not full flow statistics,
  and its training code was not part of the original project.
- Data sources are a dataset replay, simulations and local host snapshots. There is no SIEM, EDR or
  network-tap integration.
- State that lives in process memory (live replay, runtime LLM switch) requires a single backend process.
- Single analyst role; no login.

Ideas for future work:

- User accounts and roles (analyst / admin) with Django auth, audit log of decisions.
- Retrain the network model on full flow features (e.g. CICFlowMeter output) and publish the training script.
- Supervised or semi-supervised insider models using analyst feedback as labels.
- Integrations: Sysmon / Wazuh / Zeek log ingestion, Sigma rule import.
- Server-Sent Events or WebSockets instead of polling for the live views.
- A celery/RQ worker so long LLM calls run outside web requests.

---

## Credits and license

- CERT Insider Threat Test Dataset r4.2, Carnegie Mellon University Software Engineering Institute.
- UNSW-NB15 network dataset, UNSW Canberra (network model artefacts from the original project).
- MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
- Original multi-agent design: Esprit School of Engineering integrated project; refactored for local,
  free-to-run operation.

The original repository did not include a license file. Until the authors choose one, all rights are
reserved by them. For an open-source release, add a `LICENSE` file (MIT is a common choice for student
projects) and check the terms of the datasets above before redistributing them.
