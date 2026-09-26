"""Tests de la liste blanche des chemins de déploiement JANUS."""

import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from janus_v2.deployment.path_policy import (  # noqa: E402
    DeploymentPathError,
    resolve_deployment_target,
)


def test_empty_request_uses_allowed_root(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    allowed_root.mkdir()

    result = resolve_deployment_target("", str(allowed_root))

    assert Path(result) == allowed_root.resolve()


def test_real_subdirectory_is_allowed(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    target = allowed_root / "finance"
    target.mkdir(parents=True)

    result = resolve_deployment_target(str(target), str(allowed_root))

    assert Path(result) == target.resolve()


def test_sibling_directory_is_rejected(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    sibling = tmp_path / "shared-private"
    allowed_root.mkdir()
    sibling.mkdir()

    with pytest.raises(DeploymentPathError, match="non autorisé"):
        resolve_deployment_target(str(sibling), str(allowed_root))


def test_traversal_outside_root_is_rejected(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    outside = tmp_path / "outside"
    allowed_root.mkdir()
    outside.mkdir()

    traversal = allowed_root / ".." / "outside"

    with pytest.raises(DeploymentPathError, match="non autorisé"):
        resolve_deployment_target(str(traversal), str(allowed_root))


def test_nonexistent_directory_is_rejected(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    allowed_root.mkdir()

    with pytest.raises(DeploymentPathError, match="introuvable"):
        resolve_deployment_target(
            str(allowed_root / "missing"),
            str(allowed_root),
        )


def test_file_cannot_be_used_as_deployment_directory(tmp_path: Path) -> None:
    allowed_root = tmp_path / "shared"
    allowed_root.mkdir()
    file_path = allowed_root / "not-a-directory.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(DeploymentPathError, match="n'est pas un dossier"):
        resolve_deployment_target(str(file_path), str(allowed_root))
