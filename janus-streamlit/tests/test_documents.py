from __future__ import annotations

import io
from zipfile import ZipFile

from janus.documents import build_honeydocx, safe_filename
from janus.models import Beacon, GeneratedContent


def test_docx_contains_two_distinct_external_sensors_and_no_macro():
    beacons = [
        Beacon("rIdJanusPixel", "http://janus.test/api/pixel/abc", "Pixel JANUS"),
        Beacon("rIdCanaryRemote", "https://canary.example/token.gif", "Canary distant"),
    ]
    content = build_honeydocx(
        artifact_id="art_test",
        content=GeneratedContent(
            title="Prévisions consolidées",
            body="Synthèse:\nLes données de travail sont fictives et cohérentes.",
            generator_mode="local-template:docx:configured",
        ),
        campaign="Revue",
        department="Finance",
        audience="Comité",
        sensitivity="Restreinte",
        beacons=beacons,
    )
    with ZipFile(io.BytesIO(content)) as archive:
        names = archive.namelist()
        relationships = archive.read("word/_rels/document.xml.rels").decode()
        document = archive.read("word/document.xml").decode()
    assert not any(name.casefold().endswith("vbaproject.bin") for name in names)
    assert 'Id="rIdJanusPixel"' in relationships
    assert 'Id="rIdCanaryRemote"' in relationships
    assert "http://janus.test/api/pixel/abc" in relationships
    assert "https://canary.example/token.gif" in relationships
    assert 'r:link="rIdJanusPixel"' in document
    assert 'r:link="rIdCanaryRemote"' in document


def test_safe_filename_removes_path_characters():
    assert safe_filename("../../Budget: T4 2026") == "Budget_T4_2026.docx"

