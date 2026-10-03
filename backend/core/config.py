"""
Central configuration.

Two sources, one object:

* ``backend/config/config.yaml`` – every NON-secret setting (models, thresholds, agents…)
* ``.env`` (repository root)      – secrets and a few convenience overrides

Usage anywhere in the backend::

    from core.config import get_config
    cfg = get_config()
    cfg.llm.provider          # "ollama"
    cfg.secrets.groq_api_key  # read from GROQ_API_KEY

The YAML is validated with pydantic, so a typo such as ``provider: olama`` fails
loudly at startup instead of silently later.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DEFAULT_CONFIG_PATH = BACKEND_DIR / "config" / "config.yaml"

ProviderName = Literal["ollama", "groq", "huggingface", "openai_compatible", "mock", "none"]
Action = Literal["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── LLM ─────────────────────────────────────────────────────────────────────
class ProviderSettings(_Strict):
    base_url: str
    model: str
    keep_alive: Optional[str] = None


class LLMFeatures(_Strict):
    data_tool_selection: bool = False
    behavior_explanation: bool = True
    risk_assessment: bool = True
    response_summary: bool = True
    attack_planning: bool = False


class LLMSettings(_Strict):
    provider: ProviderName = "ollama"
    fallback_provider: ProviderName = "none"
    temperature: float = Field(0.2, ge=0, le=2)
    max_tokens: int = Field(400, ge=16, le=8192)
    timeout_seconds: float = Field(60, gt=0)
    retry_cooldown_seconds: float = Field(30, ge=0)
    only_for_flagged_events: bool = True
    providers: Dict[str, ProviderSettings]
    features: LLMFeatures = LLMFeatures()

    @field_validator("providers")
    @classmethod
    def _known_providers(cls, v: Dict[str, ProviderSettings]):
        allowed = {"ollama", "groq", "huggingface", "openai_compatible"}
        unknown = set(v) - allowed
        if unknown:
            raise ValueError(f"unknown provider section(s): {sorted(unknown)}")
        return v


# ── Agents ──────────────────────────────────────────────────────────────────
class DataAgentSettings(_Strict):
    enabled: bool = True
    default_source: Literal["replay", "host"] = "replay"
    host_collectors: List[str] = ["system", "process", "network", "file"]
    max_events_per_collection: int = Field(300, ge=1)
    network_window_size: int = Field(25, ge=1)


class RepeatOffender(_Strict):
    window_hours: int = 24
    min_prior_events: int = 3
    penalty: float = Field(0.15, ge=0, le=1)


class RiskAgentSettings(_Strict):
    enabled: bool = True
    max_llm_adjustment: float = Field(0.3, ge=0, le=1)
    repeat_offender: RepeatOffender = RepeatOffender()


class SimpleAgent(_Strict):
    enabled: bool = True
    seed: Optional[int] = None


class AgentsSettings(_Strict):
    data_agent: DataAgentSettings = DataAgentSettings()
    attacker_agent: SimpleAgent = SimpleAgent()
    behavior_agent: SimpleAgent = SimpleAgent()
    risk_agent: RiskAgentSettings = RiskAgentSettings()
    response_agent: SimpleAgent = SimpleAgent()


# ── ML / RL ─────────────────────────────────────────────────────────────────
class BehaviorModelSettings(_Strict):
    model_path: str
    feature_columns_path: str
    score_bounds_path: str
    baselines_seed_path: str
    baselines_path: str
    scoring_mode: Literal["isolation_forest", "hybrid"] = "hybrid"
    if_weight: float = Field(0.4, ge=0, le=1)
    rules_weight: float = Field(0.6, ge=0, le=1)
    rule_weights: Dict[str, float] = {}
    anomaly_threshold: float = Field(0.4, ge=0, le=1)
    baseline_update_threshold: float = Field(0.4, ge=0, le=1)


class NetworkModelSettings(_Strict):
    scaler_path: str
    isolation_forest_path: str
    catboost_path: str
    if_weight: float = 0.4
    catboost_weight: float = 0.6
    anomaly_threshold: float = Field(0.4, ge=0, le=1)


class MLSettings(_Strict):
    behavior: BehaviorModelSettings
    network: NetworkModelSettings


class RLSettings(_Strict):
    q_table_path: str                                      # pre-trained policy (committed, read-only)
    runtime_q_table_path: str = "data/runtime/q_table.json"  # live copy updated by analyst feedback
    learning_rate: float = Field(0.1, gt=0, le=1)
    discount_factor: float = Field(0.0, ge=0, le=1)
    epsilon: float = Field(0.1, ge=0, le=1)
    learn_from_analyst_feedback: bool = True


class RiskSettings(_Strict):
    thresholds: Dict[str, float] = {"low_max": 0.4, "medium_max": 0.7}
    min_action: Dict[RiskLevel, Action] = {}
    max_action: Dict[RiskLevel, Action] = {}

    @field_validator("thresholds")
    @classmethod
    def _ordered(cls, v: Dict[str, float]):
        if not 0 <= v.get("low_max", 0.4) < v.get("medium_max", 0.7) <= 1:
            raise ValueError("thresholds must satisfy 0 <= low_max < medium_max <= 1")
        return v


class ResponseSettings(_Strict):
    require_approval_for: List[RiskLevel] = ["MEDIUM", "HIGH"]
    auto_execute_high_risk: bool = False


class TwilioSettings(_Strict):
    enabled: bool = False
    notify_levels: List[RiskLevel] = ["HIGH"]


class NotificationSettings(_Strict):
    twilio: TwilioSettings = TwilioSettings()


class RetrievalSettings(_Strict):
    enabled: bool = True
    knowledge_dir: str = "backend/rag/knowledge"
    index_dir: str = "data/runtime/rag_index"
    backend: Literal["auto", "sentence_transformers", "tfidf"] = "auto"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    top_k: int = Field(3, ge=1, le=20)


class MCPSettings(_Strict):
    transport: Literal["inprocess", "stdio"] = "inprocess"
    timeout_seconds: float = 30


class DataSettings(_Strict):
    replay_dataset_path: str
    insiders_path: str
    runtime_dir: str = "data/runtime"


class DatabaseSettings(_Strict):
    engine: Literal["sqlite", "postgres"] = "sqlite"
    sqlite_path: str = "data/runtime/soc.sqlite3"


class StreamSettings(_Strict):
    interval_seconds: float = Field(5, ge=0.5)
    batch_size: int = Field(3, ge=1, le=50)


class ThrottleSettings(_Strict):
    simulate: str = "30/min"
    ingest: str = "60/min"


class APISettings(_Strict):
    page_size: int = Field(50, ge=1, le=500)
    throttle: ThrottleSettings = ThrottleSettings()


class AppSettings(_Strict):
    name: str = "Sentinel SOC"
    environment: Literal["development", "production"] = "development"
    timezone: str = "UTC"


class Secrets(BaseModel):
    """Values that come ONLY from the environment / .env file. Never serialised."""

    django_secret_key: str = ""
    soc_api_token: str = ""
    groq_api_key: str = ""
    hf_token: str = ""
    llm_api_key: str = ""
    database_url: str = ""
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    twilio_to_number: str = ""


class AppConfig(_Strict):
    app: AppSettings = AppSettings()
    llm: LLMSettings
    agents: AgentsSettings = AgentsSettings()
    ml: MLSettings
    rl: RLSettings
    risk: RiskSettings = RiskSettings()
    response: ResponseSettings = ResponseSettings()
    notifications: NotificationSettings = NotificationSettings()
    retrieval: RetrievalSettings = RetrievalSettings()
    mcp: MCPSettings = MCPSettings()
    data: DataSettings
    database: DatabaseSettings = DatabaseSettings()
    stream: StreamSettings = StreamSettings()
    api: APISettings = APISettings()
    # populated from the environment, excluded from YAML validation
    secrets: Secrets = Field(default_factory=Secrets, exclude=True)

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def path(relative: str) -> Path:
        """Resolve a config path relative to the repository root."""
        p = Path(relative)
        return p if p.is_absolute() else (REPO_ROOT / p)

    def public_dict(self) -> dict:
        """Configuration safe to show in the UI: secrets replaced by booleans."""
        data = self.model_dump(exclude={"secrets"})
        s = self.secrets
        data["secrets_configured"] = {
            "DJANGO_SECRET_KEY": bool(s.django_secret_key),
            "SOC_API_TOKEN": bool(s.soc_api_token),
            "GROQ_API_KEY": bool(s.groq_api_key),
            "HF_TOKEN": bool(s.hf_token),
            "LLM_API_KEY": bool(s.llm_api_key),
            "DATABASE_URL": bool(s.database_url),
            "TWILIO": bool(s.twilio_account_sid and s.twilio_auth_token),
        }
        return data


# Environment variables that override YAML keys (documented in config.yaml / README).
_ENV_OVERRIDES = {
    "APP_ENV": ("app", "environment"),
    "LLM_PROVIDER": ("llm", "provider"),
    "LLM_FALLBACK_PROVIDER": ("llm", "fallback_provider"),
    "OLLAMA_BASE_URL": ("llm", "providers", "ollama", "base_url"),
    "LLM_MODEL": ("llm", "providers", "ollama", "model"),
    "GROQ_MODEL": ("llm", "providers", "groq", "model"),
    "HF_MODEL": ("llm", "providers", "huggingface", "model"),
    "OPENAI_COMPATIBLE_BASE_URL": ("llm", "providers", "openai_compatible", "base_url"),
    "OPENAI_COMPATIBLE_MODEL": ("llm", "providers", "openai_compatible", "model"),
    "EMBEDDING_MODEL": ("retrieval", "embedding_model"),
}


def load_dotenv_file() -> None:
    """Load ``.env`` from the repo root (does not override real env vars)."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # python-dotenv is in requirements; stay usable without it
        return
    load_dotenv(REPO_ROOT / ".env", override=False)


def _set_path(data: dict, keys: tuple, value: str) -> None:
    node = data
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value


def _read_secrets() -> Secrets:
    env = os.environ.get
    return Secrets(
        django_secret_key=env("DJANGO_SECRET_KEY", ""),
        soc_api_token=env("SOC_API_TOKEN", ""),
        groq_api_key=env("GROQ_API_KEY", ""),
        hf_token=env("HF_TOKEN", ""),
        llm_api_key=env("LLM_API_KEY", ""),
        database_url=env("DATABASE_URL", ""),
        twilio_account_sid=env("TWILIO_ACCOUNT_SID", ""),
        twilio_auth_token=env("TWILIO_AUTH_TOKEN", ""),
        twilio_from_number=env("TWILIO_FROM_NUMBER", ""),
        twilio_to_number=env("TWILIO_TO_NUMBER", ""),
    )


class ConfigError(RuntimeError):
    pass


def load_config(path: Optional[Path] = None) -> AppConfig:
    load_dotenv_file()
    path = Path(os.environ.get("SOC_CONFIG_PATH", "") or path or DEFAULT_CONFIG_PATH)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    for env_name, keys in _ENV_OVERRIDES.items():
        value = os.environ.get(env_name)
        if value:
            _set_path(raw, keys, value)

    try:
        cfg = AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration in {path}:\n{exc}") from exc
    cfg.secrets = _read_secrets()
    return cfg


_lock = threading.Lock()
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    global _config
    if _config is None:
        with _lock:
            if _config is None:
                _config = load_config()
    return _config


def set_runtime_llm(provider: Optional[str] = None, model: Optional[str] = None) -> AppConfig:
    """Switch LLM provider/model at runtime (used by the Settings page).

    The change lives in memory only (until the backend restarts);
    edit config.yaml / .env to make it permanent.
    """
    cfg = get_config()
    if provider:
        if provider not in ("ollama", "groq", "huggingface", "openai_compatible", "mock", "none"):
            raise ConfigError(f"Unknown provider: {provider}")
        cfg.llm.provider = provider  # type: ignore[assignment]
    if model:
        target = cfg.llm.provider
        if target not in cfg.llm.providers:
            raise ConfigError(f"Provider '{target}' has no model setting")
        cfg.llm.providers[target].model = model
    from core.llm import reset_llm_client  # local import avoids a cycle

    reset_llm_client()
    return cfg


def reset_config_cache() -> None:
    """Used by tests to reload configuration."""
    global _config
    with _lock:
        _config = None
