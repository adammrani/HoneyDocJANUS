"""Construction OOXML déterministe de DOCX sans macro, avec capteurs distincts."""

from __future__ import annotations

import hashlib
import io
import re
import unicodedata
from datetime import UTC, datetime
from html import escape
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from .models import Beacon, GeneratedContent


class DocumentError(RuntimeError):
    pass


def safe_filename(title: str) -> str:
    normalized = unicodedata.normalize("NFKD", title)
    ascii_title = normalized.encode("ascii", "ignore").decode("ascii")
    base = re.sub(r"[^a-zA-Z0-9]+", "_", ascii_title).strip("_")[:72]
    return f"{base or 'Document_confidentiel'}.docx"


def _paragraph(text: str, style: str = "Normal") -> str:
    return (
        f'<w:p><w:pPr><w:pStyle w:val="{escape(style)}"/></w:pPr>'
        f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
    )


def _beacon_drawing(beacon: Beacon, index: int) -> str:
    return f"""
    <w:p><w:r><w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0">
        <wp:extent cx="9525" cy="9525"/>
        <wp:docPr id="{index + 1}" name="Document resource {index + 1}" descr="{escape(beacon.label)}"/>
        <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
          <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
              <pic:nvPicPr><pic:cNvPr id="{index + 1}" name="resource.gif"/><pic:cNvPicPr/></pic:nvPicPr>
              <pic:blipFill><a:blip r:link="{escape(beacon.relationship_id)}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
              <pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
            </pic:pic>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing></w:r></w:p>"""


def build_honeydocx(
    *,
    artifact_id: str,
    content: GeneratedContent,
    campaign: str,
    department: str,
    audience: str,
    sensitivity: str,
    beacons: list[Beacon],
) -> bytes:
    if not beacons:
        raise DocumentError("Au moins un capteur doit être explicitement sélectionné.")
    relationship_ids = [item.relationship_id for item in beacons]
    if len(set(relationship_ids)) != len(relationship_ids):
        raise DocumentError("Deux capteurs ne peuvent pas partager le même identifiant OOXML.")

    relationships = "".join(
        (
            f'<Relationship Id="{escape(item.relationship_id)}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="{escape(item.url)}" TargetMode="External"/>'
        )
        for item in beacons
    )

    narrative: list[str] = [
        _paragraph(content.title, "Title"),
        _paragraph(f"{department} · Diffusion {sensitivity}", "Subtitle"),
        _paragraph(f"Campagne interne : {campaign}", "Caption"),
    ]
    for raw_line in content.body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith(":") and len(line) <= 80:
            narrative.append(_paragraph(line[:-1], "Heading1"))
        else:
            narrative.append(_paragraph(line, "Normal"))
    narrative.append(_paragraph(f"Diffusion prévue : {audience}", "Caption"))
    narrative.extend(_beacon_drawing(item, index) for index, item in enumerate(beacons))
    body = "".join(narrative)
    now = datetime.now(UTC).isoformat()

    files = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
          <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
          <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
          <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
        </Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
          <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
        </Relationships>""",
        "word/_rels/document.xml.rels": f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
          {relationships}
        </Relationships>""",
        "word/document.xml": f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
          xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">
          <w:body>{body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>
          <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body>
        </w:document>""",
        "word/styles.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>
          <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:spacing w:after="160" w:line="276" w:lineRule="auto"/></w:pPr></w:style>
          <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:color w:val="143F3B"/><w:sz w:val="40"/></w:rPr><w:pPr><w:spacing w:after="180"/></w:pPr></w:style>
          <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="5F6F6D"/><w:sz w:val="22"/></w:rPr></w:style>
          <w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption"/><w:basedOn w:val="Normal"/><w:rPr><w:i/><w:color w:val="66736F"/><w:sz w:val="18"/></w:rPr></w:style>
          <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:color w:val="0E7067"/><w:sz w:val="28"/></w:rPr><w:pPr><w:spacing w:before="280" w:after="120"/></w:pPr></w:style>
        </w:styles>""",
        "docProps/core.xml": f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
          xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <dc:title>{escape(content.title)}</dc:title><dc:creator>{escape(department)}</dc:creator>
          <dc:subject>{escape(campaign)}</dc:subject><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>
        </cp:coreProperties>""",
        "docProps/app.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
          <Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion>
        </Properties>""",
    }

    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        for name, value in files.items():
            archive.writestr(name, value.encode("utf-8"))
    result = output.getvalue()
    validate_docx(result, beacons)
    return result


def validate_docx(content: bytes, beacons: list[Beacon] | None = None) -> None:
    if not content.startswith(b"PK"):
        raise DocumentError("Le fichier produit n'est pas un conteneur OOXML.")
    try:
        with ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            required = {
                "[Content_Types].xml",
                "word/document.xml",
                "word/_rels/document.xml.rels",
            }
            if not required.issubset(names):
                raise DocumentError("Le DOCX produit est incomplet.")
            if any(name.casefold().endswith("vbaproject.bin") for name in names):
                raise DocumentError("Une macro inattendue est présente.")
            relationships = archive.read("word/_rels/document.xml.rels").decode("utf-8")
    except BadZipFile as exc:
        raise DocumentError("Le DOCX produit est corrompu.") from exc
    for beacon in beacons or []:
        if beacon.url not in relationships or beacon.relationship_id not in relationships:
            raise DocumentError(f"Le capteur {beacon.label} est absent du DOCX.")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

