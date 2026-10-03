"""python manage.py check_config — validate config.yaml/.env, model files and the LLM provider."""
from __future__ import annotations

from django.core.management.base import BaseCommand

from core.config import get_config
from core.llm import LLMClient


class Command(BaseCommand):
    help = "Validate configuration, model files and LLM provider connectivity."

    def add_arguments(self, parser):
        parser.add_argument("--skip-llm", action="store_true", help="do not contact the LLM provider")

    def handle(self, *args, **opts):
        cfg = get_config()  # raises a readable ConfigError if config.yaml is invalid
        ok = True
        self.stdout.write(self.style.SUCCESS("config.yaml is valid"))
        self.stdout.write(f"  environment: {cfg.app.environment}   database: {cfg.database.engine}"
                          f"   MCP transport: {cfg.mcp.transport}")
        files = {
            "behavior model": cfg.ml.behavior.model_path, "feature columns": cfg.ml.behavior.feature_columns_path,
            "score bounds": cfg.ml.behavior.score_bounds_path, "baselines seed": cfg.ml.behavior.baselines_seed_path,
            "network scaler": cfg.ml.network.scaler_path, "network IF": cfg.ml.network.isolation_forest_path,
            "network CatBoost": cfg.ml.network.catboost_path, "Q-table": cfg.rl.q_table_path,
            "replay dataset": cfg.data.replay_dataset_path, "insider labels": cfg.data.insiders_path,
        }
        for label, rel in files.items():
            exists = cfg.path(rel).exists()
            ok &= exists or label == "Q-table"
            style = self.style.SUCCESS if exists else (self.style.WARNING if label == "Q-table" else self.style.ERROR)
            self.stdout.write(style(f"  [{'ok' if exists else 'missing'}] {label}: {rel}"))
        secrets = cfg.public_dict()["secrets_configured"]
        self.stdout.write("  secrets set: " + (", ".join(k for k, v in secrets.items() if v) or "none"))
        if cfg.llm.provider == "groq" and not cfg.secrets.groq_api_key:
            ok = False
            self.stdout.write(self.style.ERROR("  llm.provider is groq but GROQ_API_KEY is empty"))
        if not opts["skip_llm"]:
            health = LLMClient(cfg).health()
            for role, h in health.items():
                if not h:
                    continue
                style = self.style.SUCCESS if h["status"] in ("online", "disabled") else self.style.WARNING
                self.stdout.write(style(f"  LLM {role}: {h['provider']} / {h['model']} → {h['status']}"
                                        f"{'  — ' + h['hint'] if h.get('hint') else ''}"))
        self.stdout.write(self.style.SUCCESS("All required files present.") if ok
                          else self.style.ERROR("Problems found — see above."))
        if not ok:
            raise SystemExit(1)
