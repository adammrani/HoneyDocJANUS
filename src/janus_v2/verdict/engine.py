from ..domain.models import (
    DecoyInstance,
    DetectionVerdict,
    SecurityEvent,
    VerdictLevel,
)


def build_verdict(
    event: SecurityEvent,
    decoy: DecoyInstance,
) -> DetectionVerdict:
    """Produit un verdict explicable avec des règles simples."""

    score = 40
    reasons = [
        "L'événement concerne un leurre actif.",
    ]

    if decoy.expected_hostname is None:
        reasons.append(
            "Aucune machine attendue n'est définie pour ce leurre."
        )
    elif event.hostname.casefold() != decoy.expected_hostname.casefold():
        score += 30
        reasons.append(
            f"Machine inattendue : {event.hostname} au lieu de "
            f"{decoy.expected_hostname}."
        )
    else:
        reasons.append(
            "La machine correspond à la machine attendue."
        )

    if decoy.expected_user is None:
        reasons.append(
            "Aucun utilisateur attendu n'est défini pour ce leurre."
        )
    elif event.user.casefold() != decoy.expected_user.casefold():
        score += 30
        reasons.append(
            f"Utilisateur inattendu : {event.user} au lieu de "
            f"{decoy.expected_user}."
        )
    else:
        reasons.append(
            "L'utilisateur correspond à l'utilisateur attendu."
        )

    if score >= 90:
        level = VerdictLevel.CRITICAL
    elif score >= 70:
        level = VerdictLevel.SUSPECT
    elif score >= 50:
        level = VerdictLevel.MEDIUM
    else:
        level = VerdictLevel.LOW

    return DetectionVerdict(
        level=level,
        score=score,
        reasons=reasons,
        decoy_instance_id=decoy.instance_id,
        event_id=event.event_id,
    )
