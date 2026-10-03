"""
Local retrieval-augmented generation (RAG) over the cybersecurity knowledge base.

    rag/knowledge/*.md ─► chunks ─► embeddings ─► vector index ─► top-k chunks ─► LLM prompt
                                     │
                                     ├─ sentence-transformers + FAISS  (preferred, fully local)
                                     └─ scikit-learn TF-IDF            (automatic fallback — no torch needed)

Everything runs locally and for free. The index is cached in data/runtime/rag_index
and rebuilt automatically when a knowledge file changes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import numpy as np

from core.config import AppConfig, get_config

logger = logging.getLogger("soc.rag")


@dataclass
class Chunk:
    doc: str
    title: str
    text: str

    def to_dict(self, score: Optional[float] = None) -> dict:
        d = {"source": self.doc, "title": self.title, "text": self.text}
        if score is not None:
            d["score"] = round(float(score), 4)
        return d


def chunk_markdown(path: Path, max_chars: int = 900) -> List[Chunk]:
    """Split a markdown file on headings; long sections are split on paragraphs."""
    text = path.read_text(encoding="utf-8")
    chunks: List[Chunk] = []
    sections = re.split(r"(?m)^(?=#{1,3} )", text)
    for section in sections:
        section = section.strip()
        if not section:
            continue
        lines = section.splitlines()
        title = lines[0].lstrip("#").strip() if lines[0].startswith("#") else path.stem
        body = section
        while len(body) > max_chars:
            cut = body.rfind("\n\n", 0, max_chars)
            cut = cut if cut > 200 else max_chars
            chunks.append(Chunk(path.name, title, body[:cut].strip()))
            body = body[cut:]
        if body.strip():
            chunks.append(Chunk(path.name, title, body.strip()))
    return chunks


class Retriever:
    def __init__(self, cfg: Optional[AppConfig] = None):
        self.cfg = cfg or get_config()
        self._lock = threading.Lock()
        self.chunks: List[Chunk] = []
        self.backend: Optional[str] = None
        self.error: Optional[str] = None
        self._index = None       # faiss index or tf-idf matrix
        self._encoder = None     # SentenceTransformer or TfidfVectorizer

    # ── build ─────────────────────────────────────────────────────────────
    def _fingerprint(self, files: List[Path]) -> str:
        h = hashlib.sha256()
        for f in files:
            h.update(f.name.encode())
            h.update(f.read_bytes())
        h.update(self.cfg.retrieval.embedding_model.encode())
        return h.hexdigest()[:16]

    def _ensure(self) -> None:
        if self.backend or self.error:
            return
        with self._lock:
            if self.backend or self.error:
                return
            r = self.cfg.retrieval
            kdir = self.cfg.path(r.knowledge_dir)
            files = sorted(kdir.glob("*.md"))
            if not files:
                self.error = f"No knowledge files in {kdir}"
                return
            self.chunks = [c for f in files for c in chunk_markdown(f)]
            texts = [f"{c.title}\n{c.text}" for c in self.chunks]
            if r.backend in ("auto", "sentence_transformers"):
                try:
                    self._build_dense(texts, self._fingerprint(files))
                    self.backend = "sentence_transformers+faiss"
                except ImportError as exc:
                    if r.backend == "sentence_transformers":
                        self.error = f"{exc}. Install: pip install -r backend/requirements-optional.txt"
                        return
                    logger.info("sentence-transformers/faiss not installed — using TF-IDF retrieval")
                except Exception as exc:
                    logger.warning("Dense index failed — using TF-IDF", extra={"error": str(exc)})
            if self.backend is None:
                from sklearn.feature_extraction.text import TfidfVectorizer

                self._encoder = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
                self._index = self._encoder.fit_transform(texts)
                self.backend = "tfidf"
            logger.info("Knowledge index ready", extra={"backend": self.backend, "chunks": len(self.chunks)})

    def _build_dense(self, texts: List[str], fingerprint: str) -> None:
        import faiss  # noqa: F401  (ImportError → fallback)
        from sentence_transformers import SentenceTransformer

        index_dir = self.cfg.path(self.cfg.retrieval.index_dir)
        index_dir.mkdir(parents=True, exist_ok=True)
        index_file = index_dir / f"kb_{fingerprint}.faiss"
        self._encoder = SentenceTransformer(self.cfg.retrieval.embedding_model)
        if index_file.exists():
            self._index = faiss.read_index(str(index_file))
            return
        emb = self._encoder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        emb = np.asarray(emb, dtype="float32")
        index = faiss.IndexFlatIP(emb.shape[1])  # cosine similarity on normalised vectors
        index.add(emb)
        faiss.write_index(index, str(index_file))
        (index_dir / f"kb_{fingerprint}.json").write_text(json.dumps([c.to_dict() for c in self.chunks]))
        self._index = index

    # ── query ─────────────────────────────────────────────────────────────
    def search(self, query: str, k: Optional[int] = None) -> List[dict]:
        if not self.cfg.retrieval.enabled:
            return []
        self._ensure()
        if self.error or not self.chunks:
            return []
        k = min(k or self.cfg.retrieval.top_k, len(self.chunks))
        if self.backend == "tfidf":
            q = self._encoder.transform([query])
            sims = (self._index @ q.T).toarray().ravel()
            order = np.argsort(-sims)[:k]
            return [self.chunks[i].to_dict(sims[i]) for i in order if sims[i] > 0]
        emb = np.asarray(self._encoder.encode([query], normalize_embeddings=True), dtype="float32")
        scores, idx = self._index.search(emb, k)
        return [self.chunks[i].to_dict(s) for s, i in zip(scores[0], idx[0]) if i >= 0]

    def status(self) -> dict:
        if not self.cfg.retrieval.enabled:
            return {"status": "disabled"}
        self._ensure()
        return {"status": "error" if self.error else "ready", "backend": self.backend, "error": self.error,
                "chunks": len(self.chunks), "embedding_model": self.cfg.retrieval.embedding_model
                if self.backend and self.backend.startswith("sentence") else None}


def format_context(results: List[dict], max_chars: int = 1800) -> str:
    """Render retrieved chunks for a prompt."""
    out, used = [], 0
    for r in results:
        piece = f"[{r['source']} › {r['title']}]\n{r['text']}"
        if used + len(piece) > max_chars:
            break
        out.append(piece)
        used += len(piece)
    return "\n\n".join(out)


_retriever: Optional[Retriever] = None


def get_retriever() -> Retriever:
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    return _retriever
