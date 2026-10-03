#!/usr/bin/env python
"""
Build (or rebuild) the local knowledge-base index and run a test query.

With sentence-transformers + faiss installed (requirements-optional.txt) this
downloads the embedding model once from Hugging Face and caches a FAISS index in
data/runtime/rag_index/. Without them it uses the TF-IDF fallback (no download).

Usage (repository root):
    python scripts/build_rag_index.py "usb exfiltration after hours"
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from rag.retriever import get_retriever  # noqa: E402


def main() -> None:
    query = " ".join(sys.argv[1:]) or "first time USB device and upload to wikileaks"
    r = get_retriever()
    print(r.status())
    for hit in r.search(query, k=3):
        print(f"\n[{hit['score']:.3f}] {hit['source']} › {hit['title']}\n{hit['text'][:300]}…")


if __name__ == "__main__":
    main()
