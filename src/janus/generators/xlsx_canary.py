"""Ajout d'un beacon Canarytoken externe à un classeur XLSX.

Le mécanisme reproduit le principe du modèle Microsoft Excel officiel de
Canarytokens : une image transparente est déclarée dans le dessin OOXML, puis
sa relation est convertie en ressource HTTP externe. Excel contacte cette URL
à l'ouverture du classeur, sans VBA et sans macro.
"""

from __future__ import annotations

import base64
import os
import tempfile
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, ZipFile

from openpyxl import Workbook
from openpyxl.drawing.image import Image


_RELATIONSHIP_NAMESPACE = (
    "http://schemas.openxmlformats.org/package/2006/relationships"
)
_TRANSPARENT_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+M8QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def _validate_token_url(token_url: str) -> str:
    value = (token_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Le token XLSX doit utiliser une URL HTTP(S) valide.")
    return value


def attach_placeholder_image(workbook: Workbook, worksheet, token_url: str) -> None:
    """Attache le pixel qui sera converti en image externe lors de la sauvegarde."""
    if not token_url:
        return
    _validate_token_url(token_url)
    pixel_stream = BytesIO(_TRANSPARENT_PIXEL)
    pixel = Image(pixel_stream)
    pixel.width = 1
    pixel.height = 1
    worksheet.add_image(pixel, "A1")
    workbook._janus_canary_stream = pixel_stream


def _patch_relationships(xml_bytes: bytes, token_url: str) -> tuple[bytes, int]:
    root = ElementTree.fromstring(xml_bytes)
    patched = 0
    for relationship in root:
        if not relationship.tag.endswith("Relationship"):
            continue
        relation_type = relationship.attrib.get("Type", "")
        target = relationship.attrib.get("Target", "")
        if relation_type.endswith("/image") and "media/" in target:
            relationship.set("Target", token_url)
            relationship.set("TargetMode", "External")
            patched += 1

    if not patched:
        return xml_bytes, 0

    ElementTree.register_namespace("", _RELATIONSHIP_NAMESPACE)
    return (
        ElementTree.tostring(
            root,
            encoding="utf-8",
            xml_declaration=True,
        ),
        patched,
    )


def inject_external_image_beacon(
    workbook_path: str | os.PathLike[str],
    token_url: str,
) -> None:
    """Convertit l'image transparente locale en relation HTTP externe."""
    url = _validate_token_url(token_url)
    path = Path(workbook_path)
    temporary = tempfile.NamedTemporaryFile(
        mode="wb",
        suffix=".xlsx",
        prefix=f".{path.stem}-",
        dir=path.parent,
        delete=False,
    )
    temporary_path = Path(temporary.name)
    temporary.close()
    patched = 0

    try:
        with ZipFile(path, "r") as source, ZipFile(
            temporary_path,
            "w",
            compression=ZIP_DEFLATED,
        ) as destination:
            for item in source.infolist():
                contents = source.read(item.filename)
                if (
                    item.filename.startswith("xl/drawings/_rels/")
                    and item.filename.endswith(".rels")
                ):
                    contents, count = _patch_relationships(contents, url)
                    patched += count
                destination.writestr(item, contents)

        if patched != 1:
            raise ValueError(
                "Le classeur doit contenir exactement une relation d'image "
                f"Canarytoken ; relations trouvées : {patched}."
            )
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def inspect_external_image_beacon(
    workbook_path: str | os.PathLike[str],
) -> dict:
    """Inspecte le ZIP OOXML sans déclencher le token."""
    targets: list[str] = []
    macro_parts: list[str] = []
    with ZipFile(workbook_path, "r") as archive:
        for name in archive.namelist():
            lowered = name.casefold()
            if "vbaproject" in lowered or lowered.endswith(".bin"):
                macro_parts.append(name)
            if not (
                name.startswith("xl/drawings/_rels/")
                and name.endswith(".rels")
            ):
                continue
            root = ElementTree.fromstring(archive.read(name))
            for relationship in root:
                if (
                    relationship.attrib.get("Type", "").endswith("/image")
                    and relationship.attrib.get("TargetMode") == "External"
                ):
                    targets.append(relationship.attrib.get("Target", ""))
    return {
        "external_image_targets": targets,
        "macro_parts": macro_parts,
        "valid": len(targets) == 1 and not macro_parts,
    }


class CanarytokenWorkbook(Workbook):
    """Workbook openpyxl qui applique le patch Canarytoken après sauvegarde."""

    def __init__(self, token_url: str = "") -> None:
        super().__init__()
        self._janus_canary_url = (
            _validate_token_url(token_url) if token_url else ""
        )
        self._janus_canary_stream = None

    def save(self, filename) -> None:
        super().save(filename)
        if self._janus_canary_url:
            if not isinstance(filename, (str, os.PathLike)):
                raise TypeError(
                    "Un chemin de fichier est requis pour sauvegarder un "
                    "classeur Canarytoken."
                )
            inject_external_image_beacon(filename, self._janus_canary_url)
