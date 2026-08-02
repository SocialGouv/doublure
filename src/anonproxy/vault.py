"""Coffre des correspondances substitut ↔ valeur réelle (SQLite).

Le coffre vit HORS du dépôt (défaut : ``~/.local/state/anonproxy/vault.db``,
cf. réponse §3.5 : local, même utilisateur — gap assumé et documenté).

Garanties structurelles :

- **Injectivité** (D6) : contrainte d'unicité SQL sur ``(scope, surrogate)``
  ET sur ``(scope, etype, real)``. Une collision est une erreur d'intégrité
  remontée à l'appelant, jamais un écrasement silencieux.
- **Fail-closed** (D5) : coffre illisible ⇒ ``VaultUnavailableError``. Aucun
  mode dégradé, aucune supposition.
- Les **secrets ne sont jamais stockés** : ils ne transitent pas par ce module
  (D4) — le moteur les dérive sans persistance.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

DEFAULT_VAULT_PATH = Path.home() / ".local" / "state" / "anonproxy" / "vault.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mapping (
    scope      TEXT NOT NULL,
    etype      TEXT NOT NULL,
    real       TEXT NOT NULL,
    surrogate  TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (scope, etype, real)
);
-- injectivité : un substitut ne peut désigner deux réels dans une portée
CREATE UNIQUE INDEX IF NOT EXISTS idx_surrogate_unique ON mapping (scope, surrogate);
CREATE INDEX IF NOT EXISTS idx_scope ON mapping (scope);
"""


class VaultUnavailableError(RuntimeError):
    """Le coffre est inaccessible : on refuse de continuer (fail-closed)."""


class SurrogateConflict(RuntimeError):
    """Le substitut proposé est déjà pris par une autre valeur réelle."""


class Vault:
    """Accès SQLite au coffre. Sûr vis-à-vis des threads (connexion sérialisée)."""

    def __init__(self, path: str | Path | None = None, *, create_parents: bool = True):
        self.path = Path(path) if path is not None else DEFAULT_VAULT_PATH
        self._lock = threading.RLock()
        # Incrémenté à chaque nouvelle correspondance : permet à l'appelant de
        # savoir si sa vue est encore à jour sans relire toute la table.
        self.version = 0
        try:
            if create_parents:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            elif not self.path.parent.is_dir():
                raise FileNotFoundError(f"répertoire parent absent : {self.path.parent}")
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise VaultUnavailableError(f"coffre indisponible ({self.path}) : {exc}") from exc

    # -- lecture ------------------------------------------------------------ #

    def get_surrogate(self, scope: str, etype: str, real: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT surrogate FROM mapping WHERE scope=? AND etype=? AND real=?",
                (scope, etype, real),
            ).fetchone()
        return row[0] if row else None

    def get_real(self, scope: str, surrogate: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT real FROM mapping WHERE scope=? AND surrogate=?", (scope, surrogate)
            ).fetchone()
        return row[0] if row else None

    def real_exists(self, scope: str, real: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mapping WHERE scope=? AND real=? LIMIT 1", (scope, real)
            ).fetchone()
        return row is not None

    def view(self, scope: str, *, include_internal: bool = False) -> dict[str, str]:
        """Table substitut → réel pour la portée (sens entrant du walker).

        Les **attributs partagés** (types préfixés d'un `_` : zone DNS,
        sous-réseau, organisation, registry) en sont EXCLUS par défaut. Ce
        sont des aides à l'allocation, pas des entités restaurables : les
        exposer permettrait de résoudre partiellement un substitut inventé
        par le modèle — `canyon-02-prod.<zone connue>` deviendrait
        `canyon-02-prod.<zone réelle>`, un hôte fictif déguisé en hôte réel.
        Fail-closed (D5) : mieux vaut un substitut non résolu, visible comme
        tel, qu'une valeur plausible et fausse.
        """
        query = "SELECT surrogate, real FROM mapping WHERE scope=?"
        if not include_internal:
            query += r" AND etype NOT LIKE '\_%' ESCAPE '\'"
        with self._lock:
            rows = self._conn.execute(query, (scope,)).fetchall()
        return {s: r for s, r in rows}

    def count(self, scope: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM mapping WHERE scope=?", (scope,)
            ).fetchone()[0]

    # -- écriture ----------------------------------------------------------- #

    def bind(self, scope: str, etype: str, real: str, surrogate: str) -> str:
        """Lie ``real`` à ``surrogate``, atomiquement.

        Retourne le substitut effectivement en base (celui déjà lié si la
        valeur était connue). Lève ``SurrogateConflict`` si le substitut est
        déjà pris par un AUTRE réel — l'appelant doit alors régénérer.
        """
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO mapping (scope, etype, real, surrogate) VALUES (?,?,?,?)",
                        (scope, etype, real, surrogate),
                    )
                self.version += 1
                return surrogate
            except sqlite3.IntegrityError:
                existing = self.get_surrogate(scope, etype, real)
                if existing is not None:
                    return existing  # course : un autre thread a lié la même valeur
                owner = self.get_real(scope, surrogate)
                raise SurrogateConflict(
                    f"substitut déjà pris dans {scope!r} : {surrogate!r} → {owner!r}"
                ) from None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
