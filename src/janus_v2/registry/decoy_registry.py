"""Registre en mémoire des instances de leurres JANUS."""

from ..domain.models import DecoyInstance, DecoyStatus


class DecoyRegistry:
    """Stocke et retrouve les leurres connus par JANUS."""

    def __init__(self) -> None:
        self._decoys: dict[str, DecoyInstance] = {}

    def register(self, decoy: DecoyInstance) -> None:
        if decoy.instance_id in self._decoys:
            raise ValueError(
                f"L'instance {decoy.instance_id} existe déjà."
            )

        self._decoys[decoy.instance_id] = decoy

    def get_by_id(self, instance_id: str) -> DecoyInstance | None:
        return self._decoys.get(instance_id)

    def list_all(self) -> list[DecoyInstance]:
        return list(self._decoys.values())

    def list_active(self) -> list[DecoyInstance]:
        return [
            decoy
            for decoy in self._decoys.values()
            if decoy.status == DecoyStatus.ACTIVE
        ]
