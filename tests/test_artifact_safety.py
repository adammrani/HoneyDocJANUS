from pathlib import Path

from src.core.artifact_safety import find_decoy_fingerprints
from src.janus.document_assembler import assemble_document, inspect_word_beacon
from src.tactical.context_analyzer import build_prompt


def test_prompt_never_contains_the_deployment_path():
    sensitive = r"C:\Users\Analyst\Desktop\HoneyDocJANUS\data\shared"
    prompt = build_prompt("financial_report", sensitive)

    assert sensitive not in prompt
    assert "chemin local" in prompt


def test_fingerprint_detector_reports_labels_without_echoing_path():
    sensitive = r"C:\Secret\Project\drop"
    findings = find_decoy_fingerprints(
        r"Rapport JANUS rangé dans C:\Secret\Project\drop",
        sensitive_values=(sensitive,),
    )

    assert findings == ["janus_brand", "sensitive_path"]
    assert sensitive not in findings


def test_docx_inspection_confirms_beacon_and_no_macro(tmp_path: Path):
    token_url = "https://example.invalid/office/beacon.gif"
    document = assemble_document(
        content="Rapport financier confidentiel pour le comité de direction.",
        doc_type="financial_report",
        token_id="token-safe-001",
        token_url=token_url,
    )
    path = tmp_path / "rapport.docx"
    document.save(path)

    inspection = inspect_word_beacon(path, token_url)
    assert inspection == {
        "includepicture_count": 1,
        "external_image_targets": [token_url],
        "expected_url_embedded": True,
        "macro_parts": [],
        "visible_fingerprints": [],
        "valid": True,
    }
