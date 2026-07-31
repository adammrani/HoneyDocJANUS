import ntpath

from ..domain.models import DecoyInstance, DecoyStatus, SecurityEvent


def normalize_windows_path(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path.strip()))


def correlate_event(
    event: SecurityEvent,
    decoys: list[DecoyInstance],
) -> DecoyInstance | None:
    """Retourne le leurre correspondant à l'événement.

    Un leurre expiré ou révoqué n'est pas considéré comme actif.
    """

    event_path = normalize_windows_path(event.path)

    for decoy in decoys:
        if decoy.status != DecoyStatus.ACTIVE:
            continue

        decoy_path = normalize_windows_path(decoy.deployment_path)

        if event_path == decoy_path:
            return decoy

    return None
