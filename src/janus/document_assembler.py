"""
src/janus/document_assembler.py
Assemble the three JANUS layers into a single python-docx Document.

  Layer 1 — Narrative (visible): framed LLM content, rendered as headings/paras.
  Layer 2 — CI1 (invisible): hidden white 1pt instruction for LLM agents + core
            metadata. Plus the Canarytoken beacon as an INCLUDEPICTURE field.
  Layer 3 — CI3 (semi-visible): an "Annexe" page of fake credentials.

The INCLUDEPICTURE field is injected via raw OXML (`OxmlElement`), because the
python-docx public API cannot create external-content fields. When Word opens
the document with external content enabled, it fetches the token_url — that
fetch is the Canarytoken trigger.
"""

from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile

from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.shared import Pt, RGBColor
from lxml import etree

from src.core.artifact_safety import find_decoy_fingerprints
from src.janus import ci_credential_trap, ci_prompt_injection, narrative_layer
from src.core.logger import log

_WHITE = RGBColor(0xFF, 0xFF, 0xFF)
_VML_NS = "urn:schemas-microsoft-com:vml"
_OFFICE_NS = "urn:schemas-microsoft-com:office:office"
_RELATIONSHIP_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)


def inspect_word_beacon(
    document_path: str | Path,
    expected_url: str = "",
) -> dict:
    """Inspect DOCX OOXML without opening Word or contacting the token."""

    macro_parts: list[str] = []
    field_codes: list[str] = []
    external_image_targets: list[str] = []
    visible_text: list[str] = []
    with ZipFile(document_path) as archive:
        for name in archive.namelist():
            lowered = name.casefold()
            if "vbaproject" in lowered or lowered.endswith(".bin"):
                macro_parts.append(name)
            if (
                lowered.startswith("word/")
                and lowered.endswith(".xml")
                and not lowered.endswith(".rels")
            ):
                root = ElementTree.fromstring(archive.read(name))
                for element in root.iter():
                    if element.tag.endswith("}instrText") and element.text:
                        field_codes.append(element.text)
                    elif element.tag.endswith("}t") and element.text:
                        visible_text.append(element.text)
            if (
                lowered.startswith("word/_rels/")
                and lowered.endswith(".rels")
            ):
                root = ElementTree.fromstring(archive.read(name))
                for relationship in root:
                    if (
                        relationship.attrib.get("Type", "").endswith("/image")
                        and relationship.attrib.get("TargetMode") == "External"
                    ):
                        external_image_targets.append(
                            relationship.attrib.get("Target", "")
                        )

    include_fields = [
        value for value in field_codes if "INCLUDEPICTURE" in value.upper()
    ]
    fingerprints = find_decoy_fingerprints("\n".join(visible_text))
    field_url_matches = not expected_url or any(
        expected_url in field for field in include_fields
    )
    relationship_url_matches = not expected_url or (
        external_image_targets == [expected_url]
    )
    return {
        "includepicture_count": len(include_fields),
        "external_image_targets": external_image_targets,
        "expected_url_embedded": field_url_matches and relationship_url_matches,
        "macro_parts": macro_parts,
        "visible_fingerprints": fingerprints,
        "valid": (
            len(include_fields) == 1
            and len(external_image_targets) == 1
            and field_url_matches
            and relationship_url_matches
            and not macro_parts
            and not fingerprints
        ),
    }


def _add_hidden_run(paragraph, text: str) -> None:
    """Append a white, 1pt run so the text is effectively invisible in Word."""
    run = paragraph.add_run(text)
    run.font.color.rgb = _WHITE
    run.font.size = Pt(1)


def _inject_includepicture(doc: Document, token_url: str) -> None:
    """
    Insert the same footer beacon structure used by the official provider.

    Word does not reliably refresh a bare INCLUDEPICTURE field. The working
    structure needs both the field code and a 1x1 VML image whose relationship
    targets the Canarytoken URL with ``TargetMode=External``.
    """
    footer = doc.sections[0].footer
    paragraph = footer.paragraphs[0]
    relationship_id = footer.part.relate_to(
        token_url,
        RT.IMAGE,
        is_external=True,
    )

    begin_run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    begin_run._element.append(fld_begin)

    instruction_run = paragraph.add_run()
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = f' INCLUDEPICTURE "{token_url}" \\d \\* MERGEFORMAT '
    instruction_run._element.append(instr)

    separate_run = paragraph.add_run()
    fld_separate = OxmlElement("w:fldChar")
    fld_separate.set(qn("w:fldCharType"), "separate")
    separate_run._element.append(fld_separate)

    result_run = paragraph.add_run()
    pict = OxmlElement("w:pict")
    shape_type = etree.Element(
        f"{{{_VML_NS}}}shapetype",
        nsmap={"v": _VML_NS, "o": _OFFICE_NS, "r": _RELATIONSHIP_NS},
    )
    shape_type.set("id", "_x0000_t75")
    shape_type.set("coordsize", "21600,21600")
    shape_type.set(f"{{{_OFFICE_NS}}}spt", "75")
    shape_type.set(f"{{{_OFFICE_NS}}}preferrelative", "t")
    shape_type.set("path", "m@4@5l@4@11@9@11@9@5xe")
    shape_type.set("filled", "f")
    shape_type.set("stroked", "f")

    stroke = etree.Element(f"{{{_VML_NS}}}stroke")
    stroke.set("joinstyle", "miter")
    shape_type.append(stroke)

    formulas = etree.Element(f"{{{_VML_NS}}}formulas")
    for equation in (
        "if lineDrawn pixelLineWidth 0",
        "sum @0 1 0",
        "sum 0 0 @1",
        "prod @2 1 2",
        "prod @3 21600 pixelWidth",
        "prod @3 21600 pixelHeight",
        "sum @0 0 1",
        "prod @6 1 2",
        "prod @7 21600 pixelWidth",
        "sum @8 21600 0",
        "prod @7 21600 pixelHeight",
        "sum @10 21600 0",
    ):
        formula = etree.Element(f"{{{_VML_NS}}}f")
        formula.set("eqn", equation)
        formulas.append(formula)
    shape_type.append(formulas)

    path = etree.Element(f"{{{_VML_NS}}}path")
    path.set(f"{{{_OFFICE_NS}}}extrusionok", "f")
    path.set("gradientshapeok", "t")
    path.set(f"{{{_OFFICE_NS}}}connecttype", "rect")
    shape_type.append(path)

    lock = etree.Element(f"{{{_OFFICE_NS}}}lock")
    lock.set(f"{{{_VML_NS}}}ext", "edit")
    lock.set("aspectratio", "t")
    shape_type.append(lock)
    pict.append(shape_type)

    shape = etree.Element(f"{{{_VML_NS}}}shape")
    shape.set("id", "_x0000_i1025")
    shape.set("type", "#_x0000_t75")
    shape.set("style", "width:.75pt;height:.75pt")
    image_data = etree.Element(f"{{{_VML_NS}}}imagedata")
    image_data.set(f"{{{_RELATIONSHIP_NS}}}id", relationship_id)
    shape.append(image_data)
    pict.append(shape)
    result_run._element.append(pict)

    end_run = paragraph.add_run()
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    end_run._element.append(fld_end)


def _render_narrative(doc: Document, narrative_text: str) -> None:
    """Turn framed text into headings and paragraphs."""
    lines = narrative_text.split("\n")
    first_content_seen = False
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if not first_content_seen:
            doc.add_heading(line, level=1)
            first_content_seen = True
        elif len(line) < 60 and line.endswith(":"):
            doc.add_heading(line, level=2)
        else:
            doc.add_paragraph(line)


def assemble_document(
    content: str,
    doc_type: str,
    token_id: str,
    token_url: str,
    enable_janus: bool = False,
    enable_ci3: bool = False,
) -> Document:
    """
    Build and return a python-docx Document with all requested layers.
    """
    doc = Document()

    # ── Layer 1: Narrative (visible) ─────────────────────
    narrative_text = narrative_layer.format_narrative(content, doc_type)
    _render_narrative(doc, narrative_text)

    # ── Canarytoken beacon (always embedded) ─────────────
    _inject_includepicture(doc, token_url)

    # ── Layer 2: CI1 (invisible) ─────────────────────────
    if enable_janus:
        hidden_para = doc.add_paragraph()
        _add_hidden_run(hidden_para, ci_prompt_injection.get_hidden_text(token_id))

        meta = ci_prompt_injection.get_metadata_injection()
        cp = doc.core_properties
        cp.subject = meta.get("subject", "")
        cp.keywords = meta.get("keywords", "")
        cp.comments = meta.get("comments", "")
        cp.category = meta.get("category", "")

    # ── Layer 3: CI3 (semi-visible) ──────────────────────
    if enable_ci3:
        doc.add_page_break()
        creds = ci_credential_trap.generate_credentials(doc_type, token_id)
        block = ci_credential_trap.format_credentials_block(creds)
        for line in block.split("\n"):
            para = doc.add_paragraph()
            run = para.add_run(line)
            run.font.name = "Courier New"
            run.font.size = Pt(9)

    log.info(
        "Document assembled (type=%s janus=%s ci3=%s token=%s)",
        doc_type, enable_janus, enable_ci3, token_id,
    )
    return doc
