"""
Test settings: isolate every runtime file in a temp folder and use the mock LLM,
so the suite never touches data/runtime/, never needs Ollama and never calls a paid API.
"""
import os
import shutil
import tempfile
from pathlib import Path

os.environ["LLM_PROVIDER"] = "mock"
os.environ["LLM_FALLBACK_PROVIDER"] = "none"
os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-not-a-secret")

from core.config import get_config  # noqa: E402

TEST_RUNTIME = Path(tempfile.mkdtemp(prefix="soc-tests-"))
_cfg = get_config()
_q_src = _cfg.path(_cfg.rl.q_table_path)
if _q_src.exists():
    shutil.copyfile(_q_src, TEST_RUNTIME / "q_table_seed.json")
_cfg.ml.behavior.baselines_path = str(TEST_RUNTIME / "baselines.sqlite")
_cfg.rl.q_table_path = str(TEST_RUNTIME / "q_table_seed.json")
_cfg.rl.runtime_q_table_path = str(TEST_RUNTIME / "q_table.json")
_cfg.retrieval.index_dir = str(TEST_RUNTIME / "rag_index")
_cfg.database.sqlite_path = str(TEST_RUNTIME / "soc.sqlite3")
_cfg.data.runtime_dir = str(TEST_RUNTIME)
_cfg.secrets.soc_api_token = ""
_cfg.llm.retry_cooldown_seconds = 0

from soc_platform.settings import *  # noqa: E402,F401,F403

REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {"simulate": "1000/min", "ingest": "1000/min"}  # noqa: F405
