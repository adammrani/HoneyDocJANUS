"""Registre JANUS v2 alimenté par la base SQLite du déploiement."""

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any

from ..domain.models import DecoyInstance, DecoyStatus


class SqliteDecoyRegistry:
    """Expose les honeydocuments actifs comme des ``DecoyInstance``.

    Ce pont est volontairement en lecture seule : le générateur/déployeur reste
    responsable de créer les lignes, et le pipeline de détection les consulte.
    """

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path).resolve()

    def _connect(self) -> sqlite3.Connection:
        if not self._database_path.is_file():
            raise FileNotFoundError(
                f"Base JANUS introuvable : {self._database_path}"
            )

        connection = sqlite3.connect(
            f"{self._database_path.as_uri()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _optional(row: sqlite3.Row, field: str) -> Any | None:
        return row[field] if field in row.keys() else None

    @classmethod
    def _to_decoy(cls, row: sqlite3.Row) -> DecoyInstance:
        persistent_id = cls._optional(row, "instance_id")
        if not persistent_id:
            persistent_id = f"honeydoc-{row['id']}"

        created_at = cls._optional(row, "created_at")
        if created_at:
            created_at = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))

        return DecoyInstance(
            instance_id=str(persistent_id),
            filename=str(row["filename"]),
            deployment_path=str(row["filepath"]),
            expected_hostname=(
                str(value)
                if (value := cls._optional(row, "expected_hostname"))
                else None
            ),
            expected_user=(
                str(value)
                if (value := cls._optional(row, "expected_user"))
                else None
            ),
            status=DecoyStatus.ACTIVE,
            created_at=created_at,
        )

    def list_active(self) -> list[DecoyInstance]:
        """Retourne tous les leurres actifs, indépendamment de leur format."""

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM honeydocs
                WHERE active = 1
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()

        return [self._to_decoy(row) for row in rows]
