"""Politique de chemins autorisés pour les honeydocuments déployés."""

from pathlib import Path


class DeploymentPathError(ValueError):
    """Le chemin demandé n'appartient pas à la zone de déploiement autorisée."""


def _existing_directory(value: str, label: str) -> Path:
    if not value or not value.strip():
        raise DeploymentPathError(f"{label} vide.")

    path = Path(value).expanduser()
    if not path.is_absolute():
        raise DeploymentPathError(f"{label} doit être absolu : {value}")

    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DeploymentPathError(
            f"{label} introuvable : {value}"
        ) from error

    if not resolved.is_dir():
        raise DeploymentPathError(
            f"{label} n'est pas un dossier : {value}"
        )

    return resolved


def resolve_deployment_target(
    requested_path: str,
    allowed_root: str,
) -> str:
    """Valide et retourne le chemin canonique du dossier cible.

    Une valeur demandée vide sélectionne la racine configurée. Les
    sous-dossiers réels de cette racine sont acceptés, mais les chemins
    relatifs, inexistants, frères et les jonctions sortant de la racine sont
    refusés.
    """

    root = _existing_directory(allowed_root, "Racine de déploiement")
    candidate = requested_path.strip() if requested_path else str(root)
    target = _existing_directory(candidate, "Dossier de déploiement")

    try:
        target.relative_to(root)
    except ValueError as error:
        raise DeploymentPathError(
            f"Dossier non autorisé : {target}. Racine permise : {root}."
        ) from error

    return str(target)
