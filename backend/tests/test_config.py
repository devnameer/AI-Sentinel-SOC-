"""Configuration: one YAML file + .env, validated, secrets never exposed."""
from pathlib import Path

import pytest
import yaml

from core.config import DEFAULT_CONFIG_PATH, ConfigError, load_config


def _write(tmp_path: Path, mutate) -> Path:
    data = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text())
    mutate(data)
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_default_config_is_valid_and_local_first(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    cfg = load_config(DEFAULT_CONFIG_PATH)
    assert cfg.llm.provider == "ollama"            # free/local provider is the default
    assert cfg.llm.fallback_provider in ("none", "groq")
    assert cfg.database.engine == "sqlite"
    assert cfg.response.auto_execute_high_risk is False  # human approval by default
    assert cfg.notifications.twilio.enabled is False     # paid service is opt-in


def test_env_overrides_provider_and_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("LLM_MODEL", "llama3.2:3b")
    cfg = load_config(DEFAULT_CONFIG_PATH)
    assert cfg.llm.provider == "groq"
    assert cfg.llm.providers["ollama"].model == "llama3.2:3b"


def test_typo_in_provider_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    path = _write(tmp_path, lambda d: d["llm"].__setitem__("provider", "olama"))
    with pytest.raises(ConfigError, match="provider"):
        load_config(path)


def test_unknown_key_is_rejected(tmp_path):
    path = _write(tmp_path, lambda d: d["agents"]["risk_agent"].__setitem__("max_adjustmnt", 0.5))
    with pytest.raises(ConfigError):
        load_config(path)


def test_bad_thresholds_are_rejected(tmp_path):
    path = _write(tmp_path, lambda d: d["risk"].__setitem__("thresholds", {"low_max": 0.8, "medium_max": 0.5}))
    with pytest.raises(ConfigError, match="low_max"):
        load_config(path)


def test_no_secrets_in_yaml():
    import re

    text = DEFAULT_CONFIG_PATH.read_text()
    secret_like = re.compile(r"(gsk_\w{10,}|hf_\w{10,}|sk-\w{10,}|"
                             r"^\s*(api_key|token|password|secret\w*|auth_token)\s*:\s*\S+)", re.I | re.M)
    assert not secret_like.search(text), "secret-like value in config.yaml — secrets belong in .env"


def test_public_dict_hides_secret_values(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_supersecretvalue")
    cfg = load_config(DEFAULT_CONFIG_PATH)
    public = cfg.public_dict()
    assert public["secrets_configured"]["GROQ_API_KEY"] is True
    assert "gsk_supersecretvalue" not in str(public)
