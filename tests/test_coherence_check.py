"""
tests/test_coherence_check.py
Verify that check_coherence passes silently when the corpus is empty and does
not require the heavy sentence-transformers dependency for that path.
"""

from src.tactical.coherence_check import check_coherence


def test_empty_corpus_passes(tmp_path):
    empty_dir = tmp_path / "empty_corpus"
    empty_dir.mkdir()

    result = check_coherence("Un texte quelconque en français.", str(empty_dir))

    assert result["passed"] is True
    assert result["score"] == 1.0
    assert result["reason"] == "empty_corpus"


def test_nonexistent_corpus_passes():
    result = check_coherence("Texte de test.", "corpus/does_not_exist")
    assert result["passed"] is True
