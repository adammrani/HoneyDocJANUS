"""Generate credible non-Office honeydocuments without executable content.

Cloud-credential artefacts can contain official Canarytokens ``aws_keys``.
Those keys do not grant access and alert only when presented to an AWS API;
Wazuh remains the local file-interaction detection layer.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

GENERATOR_VERSION = "janus-structured/1.1"

SUPPORTED_FORMATS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "financial_report": ("docx", "xlsx", "csv", "json"),
    "hr_document": ("docx", "csv", "json"),
    "technical_config": ("docx", "env", "yaml", "json", "zip"),
    "cloud_credentials": ("env", "yaml", "json", "zip"),
}


@dataclass(frozen=True)
class GeneratedArtifact:
    """Small save-compatible wrapper used by the common deployment pipeline."""

    payload: bytes

    def save(self, destination: str) -> None:
        Path(destination).write_bytes(self.payload)


def is_supported_combination(doc_type: str, output_format: str) -> bool:
    return output_format in SUPPORTED_FORMATS_BY_TYPE.get(doc_type, ())


def _credential_values(
    token_id: str,
    credential_material: dict[str, str] | None = None,
) -> dict[str, str]:
    if credential_material:
        required = (
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_region",
        )
        missing = [name for name in required if not credential_material.get(name)]
        if missing:
            raise ValueError("Le fournisseur n'a pas fourni toutes les clés AWS.")
        access_key = credential_material["aws_access_key_id"]
        secret_key = credential_material["aws_secret_access_key"]
        region = credential_material["aws_region"]
    else:
        digest = hashlib.sha256(token_id.encode("utf-8")).digest()
        access_key = "AKIA" + hashlib.sha256(digest).hexdigest()[:16].upper()
        secret_key = base64.urlsafe_b64encode(digest + digest[:8]).decode("ascii")[:40]
        region = "eu-west-3"
    return {
        "environment": "production-eu-west-3",
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "aws_region": region,
    }


def _business_reference(doc_type: str, token_id: str, fiscal_year: int) -> str:
    suffix = hashlib.sha256(token_id.encode("utf-8")).hexdigest()[:8].upper()
    prefix = {
        "financial_report": "FIN",
        "hr_document": "RH",
        "technical_config": "CFG",
        "cloud_credentials": "CLD",
    }.get(doc_type, "DOC")
    return f"{prefix}-{fiscal_year}-{suffix}"


def _financial_rows(fiscal_year: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for month in range(1, 13):
        revenue = 182_000 + month * 3_750
        expenses = 139_000 + month * 2_980
        rows.append(
            {
                "period": f"{fiscal_year}-{month:02d}",
                "revenue_eur": revenue,
                "expenses_eur": expenses,
                "net_result_eur": revenue - expenses,
                "status": "validated" if month < 7 else "forecast",
            }
        )
    return rows


def _hr_rows() -> list[dict[str, Any]]:
    return [
        {"employee_id": "EMP-1042", "department": "Finance", "grade": "M3", "review": "scheduled"},
        {"employee_id": "EMP-1178", "department": "Operations", "grade": "M2", "review": "complete"},
        {"employee_id": "EMP-1231", "department": "IT", "grade": "S2", "review": "scheduled"},
        {"employee_id": "EMP-1315", "department": "HR", "grade": "M1", "review": "draft"},
    ]


def _structured_payload(
    *,
    doc_type: str,
    summary_text: str,
    token_id: str,
    token_url: str,
    company_name: str,
    fiscal_year: int,
    credential_material: dict[str, str] | None = None,
) -> dict[str, Any]:
    common: dict[str, Any] = {
        "classification": "CONFIDENTIEL - USAGE INTERNE",
        "company": company_name,
        "scenario": doc_type,
        "reference": _business_reference(doc_type, token_id, fiscal_year),
    }
    if doc_type == "financial_report":
        return {
            **common,
            "fiscal_year": fiscal_year,
            "summary": summary_text.strip(),
            "monthly_reporting": _financial_rows(fiscal_year),
            "document_portal": token_url,
        }
    if doc_type == "hr_document":
        return {
            **common,
            "summary": summary_text.strip(),
            "review_population": _hr_rows(),
            "review_portal": token_url,
        }
    if doc_type == "technical_config":
        return {
            **common,
            "summary": summary_text.strip(),
            "configuration": {
                "environment": "production",
                "region": "eu-west-3",
                "backup_bucket": "atlas-production-backups",
                "change_ticket": common["reference"],
                "configuration_review_url": token_url,
            },
        }
    return {
        **common,
        "summary": summary_text.strip(),
        "cloud": _credential_values(token_id, credential_material),
    }


def _to_csv(payload: dict[str, Any], doc_type: str) -> bytes:
    source_rows = (
        payload["monthly_reporting"]
        if doc_type == "financial_report"
        else payload["review_population"]
    )
    rows = [
        {
            **row,
            "document_reference": payload["reference"],
            "review_portal": payload.get("document_portal") or payload.get("review_portal"),
        }
        for row in source_rows
    ]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8-sig")


def _to_env(payload: dict[str, Any]) -> bytes:
    if "cloud" in payload:
        cloud = payload["cloud"]
        lines = [
            "# Production backup configuration - restricted",
            f"CONFIG_REFERENCE={payload['reference']}",
            f"DEPLOYMENT_ENV={cloud['environment']}",
            f"AWS_ACCESS_KEY_ID={cloud['aws_access_key_id']}",
            f"AWS_SECRET_ACCESS_KEY={cloud['aws_secret_access_key']}",
            f"AWS_DEFAULT_REGION={cloud['aws_region']}",
            "",
        ]
    else:
        config = payload["configuration"]
        lines = [
            "# Production service configuration - restricted",
            f"CONFIG_REFERENCE={payload['reference']}",
            f"DEPLOYMENT_ENV={config['environment']}",
            f"AWS_DEFAULT_REGION={config['region']}",
            f"BACKUP_BUCKET={config['backup_bucket']}",
            f"CHANGE_TICKET={config['change_ticket']}",
            f"CONFIGURATION_REVIEW_URL={config['configuration_review_url']}",
            "",
        ]
    return "\n".join(lines).encode("utf-8")


def _to_zip(payload: dict[str, Any]) -> bytes:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("backup-production/.env", _to_env(payload))
        zf.writestr(
            "backup-production/config.yaml",
            yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        )
        zf.writestr(
            "backup-production/README_INTERNAL.txt",
            (
                "Archive de reprise après incident. Accès restreint.\n"
                f"Référence : {payload['reference']}\n"
                "Valider le point de contrôle avant toute restauration.\n"
            ),
        )
        zf.writestr(
            "backup-production/manifest.json",
            json.dumps(
                {
                    "reference": payload["reference"],
                    "classification": payload["classification"],
                    "files": [".env", "config.yaml", "README_INTERNAL.txt"],
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    return archive.getvalue()


def build_structured_decoy(
    *,
    doc_type: str,
    output_format: str,
    summary_text: str,
    token_id: str,
    token_url: str,
    company_name: str = "Atlas Conseil & Industrie SA",
    fiscal_year: int = 2026,
    credential_material: dict[str, str] | None = None,
) -> GeneratedArtifact:
    """Build a validated structured honeydocument for the requested format."""

    normalized = output_format.casefold().lstrip(".")
    if normalized not in {"csv", "json", "yaml", "env", "zip"}:
        raise ValueError(f"Format structuré non pris en charge : {output_format}")
    if not is_supported_combination(doc_type, normalized):
        raise ValueError(
            f"Combinaison non prise en charge : {doc_type}/{normalized}."
        )

    payload = _structured_payload(
        doc_type=doc_type,
        summary_text=summary_text,
        token_id=token_id,
        token_url=token_url,
        company_name=company_name,
        fiscal_year=fiscal_year,
        credential_material=credential_material,
    )
    if normalized == "csv":
        body = _to_csv(payload, doc_type)
    elif normalized == "json":
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    elif normalized == "yaml":
        body = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False).encode("utf-8")
    elif normalized == "env":
        body = _to_env(payload)
    else:
        body = _to_zip(payload)

    if not body:
        raise ValueError("Le générateur structuré a produit un artefact vide.")
    return GeneratedArtifact(body)
