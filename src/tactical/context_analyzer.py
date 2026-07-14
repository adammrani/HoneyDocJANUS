"""
src/tactical/context_analyzer.py
Builds the LLM generation prompt from the strategy blueprint and the reference
corpus, so that generated decoys imitate the real internal document style.
"""

import glob
import json
import os
import random

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()


def _load_blueprint() -> dict:
    path = os.path.join(_settings.CONFIG_DIR, "strategy_blueprint.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _sample_corpus(corpus_dir: str, n: int = 3, max_chars: int = 800) -> list[str]:
    """Return up to `n` random excerpts from the corpus directory."""
    abs_dir = corpus_dir
    if not os.path.isabs(abs_dir):
        abs_dir = os.path.join(_settings.PROJECT_ROOT, corpus_dir)

    files: list[str] = []
    for ext in ("*.txt", "*.md"):
        files.extend(glob.glob(os.path.join(abs_dir, ext)))

    if not files:
        return []

    chosen = random.sample(files, min(n, len(files)))
    samples: list[str] = []
    for fp in chosen:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                samples.append(f.read(max_chars).strip())
        except OSError:
            continue
    return samples


def build_prompt(doc_type: str, target_dir: str = "") -> str:
    """
    Build a French generation prompt for the given decoy type.

    Reads persona + corpus_dir from the blueprint, samples a few real excerpts,
    and asks the model for a realistic internal document (300-500 words).
    """
    blueprint = _load_blueprint()
    decoy_types = blueprint.get("decoy_types", {})
    spec = decoy_types.get(doc_type)

    if spec is None:
        default_type = blueprint.get("default_decoy_type", "financial_report")
        spec = decoy_types.get(default_type, {})
        log.warning("Unknown doc_type %r — falling back to %r", doc_type, default_type)

    persona = spec.get("persona") or spec.get("llm_persona", "Tu es un employé de bureau.")
    corpus_dir = spec.get("corpus_dir", "")
    samples = _sample_corpus(corpus_dir) if corpus_dir else []

    corpus_block = ""
    if samples:
        joined = "\n\n---\n\n".join(samples)
        corpus_block = (
            "Voici des extraits de documents internes réels dont tu dois imiter "
            "le style, le ton et le vocabulaire (sans les recopier) :\n\n"
            f"{joined}\n\n"
        )

    context_hint = ""
    if target_dir:
        context_hint = (
            f"Le document sera déposé dans le répertoire « {target_dir} ». "
            "Choisis un sujet crédible pour cet emplacement.\n"
        )

    prompt = (
        f"{persona}\n\n"
        f"{corpus_block}"
        f"{context_hint}"
        "Rédige un document interne d'entreprise réaliste et crédible, "
        "entièrement en français, d'une longueur de 300 à 500 mots. "
        "Le document doit paraître authentique et confidentiel : titres de sections, "
        "chiffres plausibles, références internes, ton professionnel sobre. "
        "N'ajoute aucun commentaire, aucune explication, aucune note : "
        "produis uniquement le contenu du document."
    )
    return prompt
