"""Tests for non-Office honeydocument generation."""

import json
import zipfile

import yaml

from src.janus.generators.structured_decoy import (
    build_structured_decoy,
    is_supported_combination,
)


def test_cloud_env_contains_only_provider_credentials(tmp_path):
    artifact = build_structured_decoy(
        doc_type="cloud_credentials",
        output_format="env",
        summary_text="Plan de reprise cloud interne.",
        token_id="token-cloud-1234567890",
        token_url="http://localhost:8000/ping/token-cloud-1234567890",
        fiscal_year=2026,
        credential_material={
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "example-secret-with-forty-characters-0000",
            "aws_region": "us-east-1",
        },
    )
    destination = tmp_path / "cloud.env"
    artifact.save(str(destination))
    text = destination.read_text(encoding="utf-8")

    assert "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in text
    assert "AWS_SECRET_ACCESS_KEY=example-secret-with-forty-characters-0000" in text
    assert "AWS_DEFAULT_REGION=us-east-1" in text
    assert "/ping/token-cloud-1234567890" not in text
    assert "CREDENTIAL_ROTATION_PORTAL=" not in text
    assert "JANUS_REFERENCE" not in text
    assert "INTERNAL_API_" not in text
    assert "gsk_" not in text


def test_structured_json_and_yaml_are_parseable(tmp_path):
    for output_format in ("json", "yaml"):
        artifact = build_structured_decoy(
            doc_type="technical_config",
            output_format=output_format,
            summary_text="Inventaire de reprise.",
            token_id="token-config-001",
            token_url="https://example.invalid/token-config-001",
        )
        destination = tmp_path / f"config.{output_format}"
        artifact.save(str(destination))
        text = destination.read_text(encoding="utf-8")
        parsed = json.loads(text) if output_format == "json" else yaml.safe_load(text)
        assert parsed["reference"].startswith("CFG-")
        assert parsed["configuration"]["configuration_review_url"].endswith(
            "token-config-001"
        )
        assert "JANUS" not in text


def test_csv_contains_traceable_breadcrumb(tmp_path):
    artifact = build_structured_decoy(
        doc_type="financial_report",
        output_format="csv",
        summary_text="Reporting mensuel.",
        token_id="token-csv-001",
        token_url="https://example.invalid/token-csv-001",
        fiscal_year=2026,
    )
    destination = tmp_path / "report.csv"
    artifact.save(str(destination))
    text = destination.read_text(encoding="utf-8-sig")
    assert "review_portal" in text
    assert "telemetry_reference" not in text
    assert "https://example.invalid/token-csv-001" in text


def test_zip_has_expected_files_and_no_path_traversal(tmp_path):
    artifact = build_structured_decoy(
        doc_type="cloud_credentials",
        output_format="zip",
        summary_text="Archive de reprise.",
        token_id="token-zip-001",
        token_url="https://example.invalid/token-zip-001",
        credential_material={
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "example-secret-with-forty-characters-0000",
            "aws_region": "us-east-1",
        },
    )
    destination = tmp_path / "backup.zip"
    artifact.save(str(destination))

    with zipfile.ZipFile(destination) as archive:
        names = archive.namelist()
        assert "backup-production/.env" in names
        assert "backup-production/config.yaml" in names
        assert all(".." not in name.split("/") for name in names)
        env = archive.read("backup-production/.env")
        assert b"AKIAIOSFODNN7EXAMPLE" in env
        assert b"token-zip-001" not in env


def test_format_compatibility_is_explicit():
    assert is_supported_combination("financial_report", "xlsx")
    assert is_supported_combination("cloud_credentials", "env")
    assert not is_supported_combination("hr_document", "xlsx")
    assert not is_supported_combination("cloud_credentials", "docx")
