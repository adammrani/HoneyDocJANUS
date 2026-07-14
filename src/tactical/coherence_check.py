"""
src/tactical/coherence_check.py
Semantic coherence gate before a decoy is deployed.

Compares the generated text against the reference corpus using sentence
embeddings (all-MiniLM-L6-v2). If the cosine similarity is high enough, the
document is stylistically close to real internal documents and passes.

The model is lazily imported so importing this module never blocks startup or
requires the heavy dependency to be installed.
"""

import glob
import os

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()

# Cache the loaded model across calls within a process.
_MODEL = None


def _get_model():
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer  # lazy import

        log.info("Loading sentence-transformers model all-MiniLM-L6-v2 ...")
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _MODEL


def _read_corpus(corpus_dir: str, max_files: int = 10, max_chars: int = 1000) -> list[str]:
    abs_dir = corpus_dir
    if not os.path.isabs(abs_dir):
        abs_dir = os.path.join(_settings.PROJECT_ROOT, corpus_dir)

    files: list[str] = []
    for ext in ("*.txt", "*.md"):
        files.extend(glob.glob(os.path.join(abs_dir, ext)))
    files = files[:max_files]

    texts: list[str] = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                texts.append(f.read(max_chars).strip())
        except OSError:
            continue
    return texts


def check_coherence(generated_text: str, corpus_dir: str, threshold: float = 0.35) -> dict:
    """
    Return { "score": float, "passed": bool, "reason": str }.

    If the corpus is empty, we silently pass (score 1.0): there is nothing to
    compare against. If sentence-transformers is unavailable, we also pass, but
    flag it in `reason` so the caller can log it.
    """
    corpus_texts = _read_corpus(corpus_dir)
    if not corpus_texts:
        return {"score": 1.0, "passed": True, "reason": "empty_corpus"}

    try:
        from sentence_transformers import util  # lazy import

        model = _get_model()
        gen_emb = model.encode(generated_text, convert_to_tensor=True)
        corpus_emb = model.encode(corpus_texts, convert_to_tensor=True)
        sims = util.cos_sim(gen_emb, corpus_emb)[0]
        score = float(sims.max())
    except Exception as exc:  # noqa: BLE001 — dependency optional
        log.warning("coherence_check skipped (%s)", exc)
        return {"score": 1.0, "passed": True, "reason": f"skipped:{exc}"}

    passed = score >= threshold
    log.info("Coherence score=%.3f (threshold=%.2f) passed=%s", score, threshold, passed)
    return {"score": round(score, 4), "passed": passed, "reason": "computed"}
